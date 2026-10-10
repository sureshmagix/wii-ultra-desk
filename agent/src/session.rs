//! The narrow, native-owned authenticated status session runner.
//!
//! It deliberately performs one ping/pong exchange and then closes.  There is
//! no generic message, command, file, screen, or input surface here.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::timeout;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{PeerConnection, PeerConnectionEventHandler, RTCIceGatheringState};

use crate::coordinator::{AuthenticatedCoordinator, ReconnectPolicy, TurnCredentials};
use crate::identity::DeviceIdentity;
use crate::store::AgentStore;
use crate::transport::{
    accept_signed_description, build_status_peer_connection, decode_status_message,
    encode_status_message, new_session_id, signed_description, ConnectionState, IceMode,
    IceServerConfig, PeerReference, ReplayGuard, SelectedRoute, SessionEnvelope, SessionKind,
    StatusMessage, TransportConfig, MAX_SIGNAL_ENVELOPE_BYTES,
};
use crate::{AgentError, Result};

pub const SESSION_CONNECT_TIMEOUT_MS: u64 = 25_000;
pub const SESSION_LIFETIME_MS: u64 = 60_000;

#[derive(Clone, Debug)]
pub struct StatusSessionConfig {
    pub coordinator_url: String,
    pub peer: PeerReference,
    pub ice_mode: IceMode,
    pub stun_urls: Vec<String>,
    pub bind_address: String,
    /// Test-only loopback switch. Credentials are still requested and checked,
    /// but the unreachable local fixture URL is omitted from ICE gathering so
    /// a direct regression test cannot be mistaken for a relay test.
    pub local_test_skip_turn_transport: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusSessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDiagnostics {
    pub state: ConnectionState,
    pub states: Vec<ConnectionState>,
    pub route: SelectedRoute,
    pub session_id: String,
    pub reauthenticated: bool,
    pub attempts: u8,
    pub ping_completed: bool,
}

#[derive(Clone)]
struct SessionHandler {
    gathered: mpsc::Sender<()>,
    incoming: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for SessionHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gathered.try_send(());
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        if let Some(incoming) = &self.incoming {
            let _ = incoming.try_send(channel);
        }
    }
}

pub(crate) fn now_millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::SessionTimedOut)
        .and_then(|value| u64::try_from(value.as_millis()).map_err(|_| AgentError::SessionTimedOut))
}

pub(crate) fn turn_servers(credentials: TurnCredentials) -> Vec<IceServerConfig> {
    credentials
        .ice_servers
        .into_iter()
        .map(|server| IceServerConfig {
            urls: server.urls,
            username: Some(server.username),
            credential: Some(server.credential),
        })
        .collect()
}

pub(crate) fn transport_config(
    config: &StatusSessionConfig,
    turn: TurnCredentials,
) -> TransportConfig {
    let mut ice_servers = Vec::new();
    if !config.stun_urls.is_empty() {
        ice_servers.push(IceServerConfig {
            urls: config.stun_urls.clone(),
            username: None,
            credential: None,
        });
    }
    if !config.local_test_skip_turn_transport {
        ice_servers.extend(turn_servers(turn));
    }
    TransportConfig {
        ice_mode: config.ice_mode.clone(),
        ice_servers,
    }
}

fn signal_envelope(value: Value, expected_source: &PeerReference) -> Result<SessionEnvelope> {
    let object = value
        .as_object()
        .ok_or_else(|| AgentError::CoordinatorProtocol("malformed signaling event".into()))?;
    if object.get("type").and_then(Value::as_str) != Some("SIGNAL") {
        return Err(AgentError::CoordinatorProtocol(
            "expected signaling event".into(),
        ));
    }
    let source = object
        .get("source")
        .and_then(Value::as_object)
        .ok_or(AgentError::SessionIdentityOrFreshnessDenied)?;
    if source.get("locator").and_then(Value::as_str) != Some(expected_source.locator.as_str())
        || source.get("fingerprint").and_then(Value::as_str)
            != Some(expected_source.fingerprint.as_str())
    {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(AgentError::InvalidSessionEnvelope)?;
    let data = payload
        .get("data")
        .and_then(Value::as_str)
        .ok_or(AgentError::InvalidSessionEnvelope)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| AgentError::InvalidSessionEnvelope)?;
    if bytes.is_empty()
        || bytes.len() > MAX_SIGNAL_ENVELOPE_BYTES
        || URL_SAFE_NO_PAD.encode(&bytes) != data
    {
        return Err(AgentError::InvalidSessionEnvelope);
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentError::InvalidSessionEnvelope)
}

pub(crate) async fn wait_signal(
    coordinator: &mut AuthenticatedCoordinator,
    expected: &PeerReference,
) -> Result<SessionEnvelope> {
    loop {
        let event = coordinator
            .receive_message(SESSION_CONNECT_TIMEOUT_MS)
            .await?;
        if event
            .as_object()
            .and_then(|object| object.get("type"))
            .and_then(Value::as_str)
            == Some("SIGNAL")
        {
            return signal_envelope(event, expected);
        }
    }
}

pub(crate) async fn wait_gathered(receiver: &mut mpsc::Receiver<()>) -> Result<()> {
    timeout(
        Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS),
        receiver.recv(),
    )
    .await
    .map_err(|_| AgentError::SessionTimedOut)?
    .ok_or(AgentError::SessionTimedOut)
}

async fn send_ping_and_wait_pong(channel: Arc<dyn DataChannel>, session_id: &str) -> Result<()> {
    let ping = encode_status_message(&StatusMessage::Ping {
        id: session_id.into(),
        sent_at: now_millis()?,
    })?;
    timeout(Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS), async {
        let mut sent = false;
        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnOpen if !sent => {
                    channel
                        .try_send_text(
                            std::str::from_utf8(&ping)
                                .map_err(|_| AgentError::InvalidStatusMessage)?,
                        )
                        .await
                        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
                    sent = true;
                }
                DataChannelEvent::OnMessage(message) if sent => {
                    match decode_status_message(&message.data) {
                        Ok(StatusMessage::Pong { id, .. }) if id == session_id => return Ok(()),
                        _ => return Err(AgentError::InvalidStatusMessage),
                    }
                }
                _ => {}
            }
        }
        Err(AgentError::WebRtc("data channel closed before pong".into()))
    })
    .await
    .map_err(|_| AgentError::SessionTimedOut)?
}

async fn answer_one_ping(channel: Arc<dyn DataChannel>) -> Result<()> {
    timeout(Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS), async {
        while let Some(event) = channel.poll().await {
            if let DataChannelEvent::OnMessage(message) = event {
                let StatusMessage::Ping { id, .. } = decode_status_message(&message.data)? else {
                    return Err(AgentError::InvalidStatusMessage);
                };
                let pong = encode_status_message(&StatusMessage::Pong {
                    id,
                    received_at: now_millis()?,
                })?;
                channel
                    .try_send_text(
                        std::str::from_utf8(&pong).map_err(|_| AgentError::InvalidStatusMessage)?,
                    )
                    .await
                    .map_err(|error| AgentError::WebRtc(error.to_string()))?;
                // The bounded send has been admitted to SCTP, but it has not
                // necessarily reached the wire yet. Keep this one-shot status
                // channel alive briefly before the responder closes DTLS.
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Ok(());
            }
        }
        Err(AgentError::WebRtc("data channel closed before ping".into()))
    })
    .await
    .map_err(|_| AgentError::SessionTimedOut)?
}

pub(crate) async fn selected_route<P: PeerConnection>(connection: &P) -> SelectedRoute {
    let Some(sctp) = connection.sctp().await else {
        return SelectedRoute::Unknown;
    };
    let Ok(Some(pair)) = sctp
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
        .await
    else {
        return SelectedRoute::Unknown;
    };
    SelectedRoute::from_candidate_types(
        &format!("{:?}", pair.local().typ),
        &format!("{:?}", pair.remote().typ),
    )
}

/// Run one authorized status ping. Every invocation performs fresh coordinator
/// authentication, a fresh local grant check, a fresh session ID and fresh
/// TURN credentials. Callers restart this after disconnect using their native
/// service supervisor; no old SDP or coordinator socket is reusable.
pub async fn run_status_session(
    store: &AgentStore,
    identity: &DeviceIdentity,
    config: &StatusSessionConfig,
    role: StatusSessionRole,
) -> Result<SessionDiagnostics> {
    if config.local_test_skip_turn_transport
        && (!config.coordinator_url.starts_with("ws://127.0.0.1:")
            || !config.bind_address.starts_with("127.0.0.1:"))
    {
        return Err(AgentError::CoordinatorProtocol(
            "local TURN-skip mode requires loopback coordinator and bind address".into(),
        ));
    }
    let policy = ReconnectPolicy::default();
    let mut last_error = None;
    for attempt in 1..=policy.max_attempts {
        // A responder is the host-side authorization boundary. The initiator
        // only needs a current pinned peer to verify the response; requiring a
        // view grant there would create an unnecessary reverse-access grant.
        match role {
            StatusSessionRole::Initiator => {
                store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
            }
            StatusSessionRole::Responder => {
                store.authorize_desktop_view_session(
                    &config.peer.locator,
                    &config.peer.fingerprint,
                    now_millis()?,
                )?;
            }
        }
        let mut coordinator = AuthenticatedCoordinator::connect_with_retry(
            &config.coordinator_url,
            identity,
            &policy,
        )
        .await?;
        if !coordinator.session_is_current(now_millis()?) {
            return Err(AgentError::CoordinatorDenied("session_expired".into()));
        }
        eprintln!(
            "status-session state=signaling role={} attempt={attempt}",
            match role {
                StatusSessionRole::Initiator => "initiator",
                StatusSessionRole::Responder => "responder",
            }
        );
        let result = match role {
            StatusSessionRole::Initiator => {
                run_initiator(store, &mut coordinator, identity, config).await
            }
            StatusSessionRole::Responder => {
                run_responder(store, &mut coordinator, identity, config).await
            }
        };
        match result {
            Ok(mut diagnostics) => {
                diagnostics.attempts = attempt;
                return Ok(diagnostics);
            }
            Err(error) if is_retryable(&error) && attempt < policy.max_attempts => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(policy.delay_before_attempt(attempt)))
                    .await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| AgentError::SessionTimedOut))
}

fn is_retryable(error: &AgentError) -> bool {
    matches!(
        error,
        AgentError::WebRtc(_) | AgentError::CoordinatorProtocol(_) | AgentError::SessionTimedOut
    )
}

async fn run_initiator(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &StatusSessionConfig,
) -> Result<SessionDiagnostics> {
    let session_id = new_session_id();
    let turn = coordinator
        .request_turn_credentials(&config.peer, &session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let connection = build_status_peer_connection(
        &transport_config(config, turn),
        SessionHandler {
            gathered: gathered_tx,
            incoming: None,
        },
        config.bind_address.clone(),
    )
    .await?;
    let channel = connection
        .create_data_channel("wii-status-v1", None)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    let offer = connection
        .create_offer(None)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    connection
        .set_local_description(offer)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    wait_gathered(&mut gathered_rx).await?;
    let now = now_millis()?;
    let offer = signed_description(
        identity,
        config.peer.clone(),
        Some(session_id.clone()),
        SessionKind::Offer,
        &connection
            .local_description()
            .await
            .ok_or_else(|| AgentError::WebRtc("missing local offer".into()))?,
        now,
        now + SESSION_LIFETIME_MS,
    )?;
    coordinator.relay_envelope(&offer).await?;
    let answer = wait_signal(coordinator, &config.peer).await?;
    let mut replay = ReplayGuard::default();
    // Do not apply the answer if the initiating controller revoked trust in
    // this host while the coordinator exchange was in flight.
    let current = store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
    accept_signed_description(
        &connection,
        &answer,
        SessionKind::Answer,
        Some(&session_id),
        identity,
        &current,
        now_millis()?,
        &mut replay,
    )
    .await?;
    send_ping_and_wait_pong(channel, &session_id).await?;
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    Ok(SessionDiagnostics {
        state: ConnectionState::Closed,
        states: vec![
            ConnectionState::Authorizing,
            ConnectionState::Signaling,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Closed,
        ],
        route,
        session_id,
        reauthenticated: true,
        attempts: 0,
        ping_completed: true,
    })
}

async fn run_responder(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &StatusSessionConfig,
) -> Result<SessionDiagnostics> {
    let offer = wait_signal(coordinator, &config.peer).await?;
    if offer.kind != SessionKind::Offer {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    // Re-authorize immediately before remote SDP is accepted, so revocation
    // while idle cannot be bypassed by a previously opened coordinator socket.
    let current = store.authorize_desktop_view_session(
        &config.peer.locator,
        &config.peer.fingerprint,
        now_millis()?,
    )?;
    let turn = coordinator
        .request_turn_credentials(&config.peer, &offer.session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
    let connection = build_status_peer_connection(
        &transport_config(config, turn),
        SessionHandler {
            gathered: gathered_tx,
            incoming: Some(incoming_tx),
        },
        config.bind_address.clone(),
    )
    .await?;
    let mut replay = ReplayGuard::default();
    accept_signed_description(
        &connection,
        &offer,
        SessionKind::Offer,
        None,
        identity,
        &current,
        now_millis()?,
        &mut replay,
    )
    .await?;
    let answer = connection
        .create_answer(None)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    connection
        .set_local_description(answer)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    wait_gathered(&mut gathered_rx).await?;
    let now = now_millis()?;
    let answer = signed_description(
        identity,
        config.peer.clone(),
        Some(offer.session_id.clone()),
        SessionKind::Answer,
        &connection
            .local_description()
            .await
            .ok_or_else(|| AgentError::WebRtc("missing local answer".into()))?,
        now,
        now + SESSION_LIFETIME_MS,
    )?;
    coordinator.relay_envelope(&answer).await?;
    let channel = timeout(
        Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS),
        incoming_rx.recv(),
    )
    .await
    .map_err(|_| AgentError::SessionTimedOut)?
    .ok_or(AgentError::SessionTimedOut)?;
    answer_one_ping(channel).await?;
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    Ok(SessionDiagnostics {
        state: ConnectionState::Closed,
        states: vec![
            ConnectionState::Authorizing,
            ConnectionState::Signaling,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Closed,
        ],
        route,
        session_id: offer.session_id,
        reauthenticated: true,
        attempts: 0,
        ping_completed: true,
    })
}
