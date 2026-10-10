//! Authenticated desktop-view session runner.
//!
//! It reuses the signed SDP/ICE/TURN setup from the status session but keeps a
//! separate, bounded `wii-desktop-v1` protocol. Pixels originate only from the
//! native host. Input is parsed and authorized only by the native host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{PeerConnection, PeerConnectionEventHandler, RTCIceGatheringState};

use crate::coordinator::{AuthenticatedCoordinator, ReconnectPolicy, TurnCredentials};
use crate::desktop::{
    decode_desktop_message, encode_desktop_message, DesktopInput, DesktopMessage,
    NativeDesktopHost, QualityController, QualityMode,
};
use crate::identity::DeviceIdentity;
use crate::session::{
    now_millis, selected_route, wait_gathered, SESSION_CONNECT_TIMEOUT_MS, SESSION_LIFETIME_MS,
};
use crate::store::{AgentStore, UNATTENDED_LEASE_MAX_MS};
use crate::transport::{
    accept_signed_description, build_peer_connection, new_session_id, signed_description,
    ConnectionState, IceMode, IceServerConfig, PeerReference, ReplayGuard, SelectedRoute,
    SessionEnvelope, SessionKind, TransportConfig,
};
use crate::{AgentError, Result};

const DESKTOP_DATA_CHANNEL_BUFFER_BYTES: usize = 256 * 1024;
const DESKTOP_SESSION_MAX_MS: u64 = 15 * 60_000;

#[derive(Clone, Debug)]
pub struct DesktopSessionConfig {
    pub coordinator_url: String,
    pub peer: PeerReference,
    pub ice_mode: IceMode,
    pub stun_urls: Vec<String>,
    pub bind_address: String,
    pub monitor_id: Option<u32>,
    pub quality: QualityMode,
    pub control_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopSessionRole {
    Controller,
    Host,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopCommand {
    Input { input: DesktopInput },
    Quality { quality: QualityMode },
    Disconnect,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopEvent {
    State {
        state: ConnectionState,
        route: SelectedRoute,
        session_id: String,
    },
    Control {
        allowed: bool,
    },
    HostIndicator {
        active: bool,
        monitor_id: Option<u32>,
    },
    Monitor {
        monitor: crate::desktop::MonitorDescriptor,
        keyboard_layout: String,
    },
    Frame {
        sequence: u64,
        width: u32,
        height: u32,
        jpeg: String,
    },
    Stats {
        captured_frames: u64,
        sent_frames: u64,
        dropped_frames: u64,
        encode_ms: u64,
        hardware_encoder_verified: bool,
    },
    Closed {
        route: SelectedRoute,
        session_id: String,
        reauthenticated: bool,
        attempts: u8,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopSessionDiagnostics {
    pub state: ConnectionState,
    pub route: SelectedRoute,
    pub session_id: String,
    pub reauthenticated: bool,
    pub attempts: u8,
    pub captured_frames: u64,
    pub sent_frames: u64,
    pub dropped_frames: u64,
    pub hardware_encoder_verified: bool,
}

#[derive(Clone)]
struct DesktopHandler {
    gathered: mpsc::Sender<()>,
    incoming: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for DesktopHandler {
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

fn transport_config(
    config: &DesktopSessionConfig,
    credentials: TurnCredentials,
) -> TransportConfig {
    let mut ice_servers = Vec::new();
    if !config.stun_urls.is_empty() {
        ice_servers.push(IceServerConfig {
            urls: config.stun_urls.clone(),
            username: None,
            credential: None,
        });
    }
    ice_servers.extend(
        credentials
            .ice_servers
            .into_iter()
            .map(|server| IceServerConfig {
                urls: server.urls,
                username: Some(server.username),
                credential: Some(server.credential),
            }),
    );
    TransportConfig {
        ice_mode: config.ice_mode.clone(),
        ice_servers,
    }
}

fn send_event(events: &mpsc::Sender<DesktopEvent>, event: DesktopEvent) {
    // UI diagnostics are deliberately lossy rather than becoming a hidden
    // unbounded frame queue if the local Electron process is slow or absent.
    let _ = events.try_send(event);
}

async fn send_message(channel: &Arc<dyn DataChannel>, message: &DesktopMessage) -> Result<bool> {
    let bytes = encode_desktop_message(message)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| AgentError::InvalidDesktopMessage)?;
    match channel.try_send_text(text).await {
        Ok(()) => Ok(true),
        Err(error) if error.to_string().contains("SendBufferFull") => Ok(false),
        Err(error) => Err(AgentError::WebRtc(error.to_string())),
    }
}

async fn wait_channel(
    receiver: &mut mpsc::Receiver<Arc<dyn DataChannel>>,
) -> Result<Arc<dyn DataChannel>> {
    timeout(
        Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS),
        receiver.recv(),
    )
    .await
    .map_err(|_| AgentError::SessionTimedOut)?
    .ok_or(AgentError::SessionTimedOut)
}

fn signal_kind_envelope(value: Value, peer: &PeerReference) -> Result<SessionEnvelope> {
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
    if source.get("locator").and_then(Value::as_str) != Some(peer.locator.as_str())
        || source.get("fingerprint").and_then(Value::as_str) != Some(peer.fingerprint.as_str())
    {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    let data = object
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("data"))
        .and_then(Value::as_str)
        .ok_or(AgentError::InvalidSessionEnvelope)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| AgentError::InvalidSessionEnvelope)?;
    if bytes.is_empty() || bytes.len() > crate::transport::MAX_SIGNAL_ENVELOPE_BYTES {
        return Err(AgentError::InvalidSessionEnvelope);
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentError::InvalidSessionEnvelope)
}

async fn wait_desktop_signal(
    coordinator: &mut AuthenticatedCoordinator,
    peer: &PeerReference,
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
            return signal_kind_envelope(event, peer);
        }
    }
}

/// Establish a fresh desktop session. Each retry repeats the native view grant
/// and coordinator authentication; it never revives old SDP or TURN state.
pub async fn run_desktop_session(
    store: &AgentStore,
    identity: &DeviceIdentity,
    config: &DesktopSessionConfig,
    role: DesktopSessionRole,
    commands: &mut mpsc::Receiver<DesktopCommand>,
    events: mpsc::Sender<DesktopEvent>,
) -> Result<DesktopSessionDiagnostics> {
    let policy = ReconnectPolicy::default();
    let mut last_error = None;
    for attempt in 1..=policy.max_attempts {
        // The host alone authorizes desktop access.  A controller needs the
        // peer's pinned, non-revoked identity to verify signed SDP, but must
        // not have to grant the host reverse access just to view it.
        match role {
            DesktopSessionRole::Controller => {
                store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
            }
            DesktopSessionRole::Host => {
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
        let result = match role {
            DesktopSessionRole::Controller => {
                run_controller(store, &mut coordinator, identity, config, commands, &events).await
            }
            DesktopSessionRole::Host => {
                run_host(store, &mut coordinator, identity, config, commands, &events).await
            }
        };
        match result {
            Ok(mut diagnostics) => {
                diagnostics.attempts = attempt;
                return Ok(diagnostics);
            }
            Err(error) if retryable(&error) && attempt < policy.max_attempts => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(policy.delay_before_attempt(attempt)))
                    .await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or(AgentError::SessionTimedOut))
}

fn retryable(error: &AgentError) -> bool {
    matches!(
        error,
        AgentError::WebRtc(_) | AgentError::CoordinatorProtocol(_) | AgentError::SessionTimedOut
    )
}

async fn run_controller(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &DesktopSessionConfig,
    commands: &mut mpsc::Receiver<DesktopCommand>,
    events: &mpsc::Sender<DesktopEvent>,
) -> Result<DesktopSessionDiagnostics> {
    let session_id = new_session_id();
    let credentials = coordinator
        .request_turn_credentials(&config.peer, &session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let connection = build_peer_connection(
        &transport_config(config, credentials),
        DesktopHandler {
            gathered: gathered_tx,
            incoming: None,
        },
        config.bind_address.clone(),
        DESKTOP_DATA_CHANNEL_BUFFER_BYTES,
    )
    .await?;
    let channel = connection
        .create_data_channel("wii-desktop-v1", None)
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
    let envelope = signed_description(
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
    coordinator.relay_envelope(&envelope).await?;
    let answer = wait_desktop_signal(coordinator, &config.peer).await?;
    let mut replay = ReplayGuard::default();
    // Trust may have been revoked while the controller was waiting for the
    // answer. Re-read it immediately before applying remote SDP.
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
    let outcome =
        controller_loop(&connection, &session_id, channel, config, commands, events).await;
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    let (captured, sent, dropped) = outcome?;
    send_event(
        events,
        DesktopEvent::Closed {
            route: route.clone(),
            session_id: session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(DesktopSessionDiagnostics {
        state: ConnectionState::Closed,
        route,
        session_id,
        reauthenticated: true,
        attempts: 0,
        captured_frames: captured,
        sent_frames: sent,
        dropped_frames: dropped,
        hardware_encoder_verified: false,
    })
}

async fn run_host(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &DesktopSessionConfig,
    commands: &mut mpsc::Receiver<DesktopCommand>,
    events: &mpsc::Sender<DesktopEvent>,
) -> Result<DesktopSessionDiagnostics> {
    let offer = wait_desktop_signal(coordinator, &config.peer).await?;
    if offer.kind != SessionKind::Offer {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    let current = store.authorize_desktop_view_session(
        &config.peer.locator,
        &config.peer.fingerprint,
        now_millis()?,
    )?;
    let credentials = coordinator
        .request_turn_credentials(&config.peer, &offer.session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
    let connection = build_peer_connection(
        &transport_config(config, credentials),
        DesktopHandler {
            gathered: gathered_tx,
            incoming: Some(incoming_tx),
        },
        config.bind_address.clone(),
        DESKTOP_DATA_CHANNEL_BUFFER_BYTES,
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
    let envelope = signed_description(
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
    coordinator.relay_envelope(&envelope).await?;
    let channel = wait_channel(&mut incoming_rx).await?;
    let mut host = NativeDesktopHost::open(config.monitor_id)?;
    let monitor = host.descriptor();
    send_event(
        events,
        DesktopEvent::State {
            state: ConnectionState::Connected,
            route: selected_route(&connection).await,
            session_id: offer.session_id.clone(),
        },
    );
    send_event(
        events,
        DesktopEvent::HostIndicator {
            active: true,
            monitor_id: Some(monitor.id),
        },
    );
    let tracked_unattended = if store.unattended_service_mode() {
        let now = now_millis()?;
        store.record_unattended_session(
            &offer.session_id,
            &config.peer.fingerprint,
            "desktop",
            now,
            now.saturating_add(UNATTENDED_LEASE_MAX_MS),
        )?;
        true
    } else {
        false
    };
    let outcome = host_loop(
        store,
        &mut host,
        channel,
        config,
        commands,
        events,
        &offer.session_id,
    )
    .await;
    if tracked_unattended {
        let _ = store.close_unattended_session(
            &offer.session_id,
            now_millis().unwrap_or(0),
            "desktop_session_closed",
        );
    }
    let cleanup = host.release_all();
    send_event(
        events,
        DesktopEvent::HostIndicator {
            active: false,
            monitor_id: Some(monitor.id),
        },
    );
    let route = selected_route(&connection).await;
    let close = connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()));
    cleanup?;
    close?;
    let (captured, sent, dropped) = outcome?;
    send_event(
        events,
        DesktopEvent::Closed {
            route: route.clone(),
            session_id: offer.session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(DesktopSessionDiagnostics {
        state: ConnectionState::Closed,
        route,
        session_id: offer.session_id,
        reauthenticated: true,
        attempts: 0,
        captured_frames: captured,
        sent_frames: sent,
        dropped_frames: dropped,
        hardware_encoder_verified: false,
    })
}

async fn controller_loop<P: PeerConnection>(
    connection: &P,
    session_id: &str,
    channel: Arc<dyn DataChannel>,
    config: &DesktopSessionConfig,
    commands: &mut mpsc::Receiver<DesktopCommand>,
    events: &mpsc::Sender<DesktopEvent>,
) -> Result<(u64, u64, u64)> {
    let deadline = tokio::time::sleep(Duration::from_millis(DESKTOP_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut opened = false;
    let mut input_sequence = 0_u64;
    let mut received_frames = 0_u64;
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => {
                    opened = true;
                    if !send_message(&channel, &DesktopMessage::Hello { version: crate::desktop::DESKTOP_PROTOCOL_VERSION, control_requested: config.control_requested, quality: config.quality }).await? { return Err(AgentError::WebRtc("desktop hello backpressured".into())); }
                    send_event(events, DesktopEvent::State { state: ConnectionState::Connected, route: selected_route(connection).await, session_id: session_id.into() });
                }
                Some(DataChannelEvent::OnMessage(message)) => match decode_desktop_message(&message.data)? {
                    DesktopMessage::Control { allowed } => send_event(events, DesktopEvent::Control { allowed }),
                    DesktopMessage::Monitor { monitor, keyboard_layout } => send_event(events, DesktopEvent::Monitor { monitor, keyboard_layout }),
                    DesktopMessage::Frame { sequence, width, height, jpeg } => { received_frames += 1; send_event(events, DesktopEvent::Frame { sequence, width, height, jpeg }); }
                    DesktopMessage::Stats { captured_frames, sent_frames, dropped_frames, encode_ms } => send_event(events, DesktopEvent::Stats { captured_frames, sent_frames, dropped_frames, encode_ms, hardware_encoder_verified: false }),
                    DesktopMessage::Disconnect { .. } => return Ok((received_frames, 0, 0)),
                    _ => return Err(AgentError::InvalidDesktopMessage),
                },
                Some(_) => {},
                None => return Ok((received_frames, 0, 0)),
            },
            command = commands.recv() => match command {
                Some(DesktopCommand::Input { input }) => {
                    if !config.control_requested || !opened { continue; }
                    input_sequence += 1;
                    if !send_message(&channel, &DesktopMessage::Input { sequence: input_sequence, input }).await? { return Err(AgentError::WebRtc("desktop input backpressured".into())); }
                }
                Some(DesktopCommand::Quality { quality }) if opened => { let _ = send_message(&channel, &DesktopMessage::Quality { quality }).await?; }
                Some(DesktopCommand::Disconnect) | None => {
                    if opened { let _ = send_message(&channel, &DesktopMessage::Disconnect { reason: "local_disconnect".into() }).await; }
                    return Ok((received_frames, 0, 0));
                }
                _ => {},
            }
        }
    }
}

async fn host_loop(
    store: &AgentStore,
    host: &mut NativeDesktopHost,
    channel: Arc<dyn DataChannel>,
    config: &DesktopSessionConfig,
    commands: &mut mpsc::Receiver<DesktopCommand>,
    events: &mpsc::Sender<DesktopEvent>,
    session_id: &str,
) -> Result<(u64, u64, u64)> {
    let deadline = tokio::time::sleep(Duration::from_millis(DESKTOP_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut tick = interval(Duration::from_millis(20));
    let mut quality = QualityController::new(config.quality);
    let mut opened = false;
    let mut hello = false;
    let mut control_requested = false;
    let mut control_advertised = false;
    let mut last_input_sequence = 0_u64;
    let mut frame_sequence = 0_u64;
    let mut captured = 0_u64;
    let mut sent = 0_u64;
    let mut dropped = 0_u64;
    let mut encode_ms = 0_u64;
    let mut last_frame = Instant::now() - Duration::from_secs(1);
    let mut last_stats = Instant::now();
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            _ = tick.tick() => {
                store.unattended_session_lease_current(
                    session_id,
                    &config.peer.fingerprint,
                    now_millis()?,
                )?;
                let profile = quality.profile();
                if !opened || !hello || last_frame.elapsed() < Duration::from_millis(1_000 / u64::from(profile.frames_per_second)) { continue; }
                // Stop capture immediately when the host-side view grant is no longer current.
                store.authorize_desktop_view_session(&config.peer.locator, &config.peer.fingerprint, now_millis()?)?;
                if let Some(monitor) = host.refresh_monitor()? {
                    if !send_message(&channel, &DesktopMessage::Monitor { monitor: monitor.clone(), keyboard_layout: "system_unicode_text_and_named_keys".into() }).await? { return Err(AgentError::WebRtc("desktop monitor change announcement backpressured".into())); }
                    send_event(events, DesktopEvent::Monitor { monitor, keyboard_layout: "system_unicode_text_and_named_keys".into() });
                }
                last_frame = Instant::now();
                let started = Instant::now();
                match host.capture(profile) {
                    Ok(frame) => {
                        captured += 1;
                        encode_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                        frame_sequence += 1;
                        let message = DesktopMessage::Frame { sequence: frame_sequence, width: frame.width, height: frame.height, jpeg: STANDARD_NO_PAD.encode(frame.jpeg) };
                        let admitted = send_message(&channel, &message).await?;
                        if admitted { sent += 1; } else { dropped += 1; }
                        quality.observe(encode_ms, admitted);
                    }
                    Err(AgentError::InvalidDesktopMessage) => { dropped += 1; quality.observe(encode_ms.max(1), false); }
                    Err(error) => return Err(error),
                }
                if last_stats.elapsed() >= Duration::from_secs(2) {
                    last_stats = Instant::now();
                    let _ = send_message(&channel, &DesktopMessage::Stats { captured_frames: captured, sent_frames: sent, dropped_frames: dropped, encode_ms }).await?;
                    send_event(events, DesktopEvent::Stats { captured_frames: captured, sent_frames: sent, dropped_frames: dropped, encode_ms, hardware_encoder_verified: false });
                }
            },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => {
                    opened = true;
                    let descriptor = host.descriptor();
                    if !send_message(&channel, &DesktopMessage::Monitor { monitor: descriptor.clone(), keyboard_layout: "system_unicode_text_and_named_keys".into() }).await? { return Err(AgentError::WebRtc("desktop monitor announcement backpressured".into())); }
                    send_event(events, DesktopEvent::Monitor { monitor: descriptor, keyboard_layout: "system_unicode_text_and_named_keys".into() });
                }
                Some(DataChannelEvent::OnMessage(message)) => match decode_desktop_message(&message.data)? {
                    DesktopMessage::Hello { control_requested: requested, quality: requested_quality, .. } if opened && !hello => {
                        hello = true;
                        control_requested = requested;
                        control_advertised = requested && store.authorize_desktop_control_session(&config.peer.locator, &config.peer.fingerprint, now_millis()?).is_ok();
                        if !send_message(&channel, &DesktopMessage::Control { allowed: control_advertised }).await? { return Err(AgentError::WebRtc("desktop control capability backpressured".into())); }
                        send_event(events, DesktopEvent::Control { allowed: control_advertised });
                        quality.set_requested(requested_quality);
                    }
                    DesktopMessage::Input { sequence, input } if hello && control_requested && control_advertised => {
                        if sequence != last_input_sequence.saturating_add(1) { return Err(AgentError::InvalidDesktopMessage); }
                        // A view-only connection never reaches this check. A control grant is
                        // re-evaluated at the host for every ordered input event.
                        store.authorize_desktop_control_session(&config.peer.locator, &config.peer.fingerprint, now_millis()?).map_err(|_| AgentError::DesktopControlDenied)?;
                        host.apply_input(input)?;
                        last_input_sequence = sequence;
                    }
                    DesktopMessage::Quality { quality: requested } if hello => quality.set_requested(requested),
                    DesktopMessage::Disconnect { .. } => return Ok((captured, sent, dropped)),
                    _ => return Err(AgentError::InvalidDesktopMessage),
                },
                Some(_) => {},
                None => return Ok((captured, sent, dropped)),
            },
            command = commands.recv() => match command {
                Some(DesktopCommand::Disconnect) | None => { if opened { let _ = send_message(&channel, &DesktopMessage::Disconnect { reason: "host_disconnect".into() }).await; } return Ok((captured, sent, dropped)); }
                Some(DesktopCommand::Quality { quality: requested }) => quality.set_requested(requested),
                Some(DesktopCommand::Input { .. }) => {},
            }
        }
    }
}
