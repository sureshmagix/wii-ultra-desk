//! Phase 2B's narrow WebRTC transport boundary.
//!
//! This module deliberately carries only signed offer/answer material and a
//! bounded status data channel.  It is not a command/RPC channel.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfiguration,
    RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy, RTCSessionDescription,
};
use webrtc::runtime::{Runtime, TokioRuntime};

use crate::identity::{verify_signature, DeviceIdentity};
use crate::store::AuthorizedSessionPeer;
use crate::{AgentError, Result};

const SESSION_DOMAIN: &[u8] = b"WII-ULTRA-DESK/WEBRTC-SESSION/V1\0";
pub const MAX_SIGNAL_BODY_BYTES: usize = 6_144;
pub const MAX_SIGNAL_ENVELOPE_BYTES: usize = 8_192;
pub const MAX_STATUS_MESSAGE_BYTES: usize = 1_024;
pub const STATUS_SEND_BUFFER_BYTES: usize = 16 * 1024;
pub const MAX_REPLAY_ENTRIES: usize = 128;
pub const MAX_SESSION_LIFETIME_MS: u64 = 60_000;
pub const CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    Offer,
    Answer,
    Cancel,
    #[serde(rename = "ice-candidate")]
    IceCandidate,
    #[serde(rename = "revocation")]
    Revocation,
    #[serde(rename = "revocation-ack")]
    RevocationAck,
}

impl SessionKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
            Self::Cancel => "cancel",
            Self::IceCandidate => "ice-candidate",
            Self::Revocation => "revocation",
            Self::RevocationAck => "revocation-ack",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerReference {
    pub locator: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionEnvelope {
    pub version: u8,
    pub session_id: String,
    pub nonce: String,
    pub kind: SessionKind,
    pub created_at: u64,
    pub expires_at: u64,
    pub source: PeerReference,
    pub destination: PeerReference,
    /// Base64url-encoded SDP or serialized candidate, never an arbitrary binary blob.
    pub body: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IceMode {
    Automatic,
    RelayOnlyDiagnostic,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Idle,
    Authorizing,
    Signaling,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
    Cancelled,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedRoute {
    HostDirect,
    ServerReflexiveDirect,
    Relayed,
    Unknown,
}

impl SelectedRoute {
    pub fn from_candidate_types(local: &str, remote: &str) -> Self {
        if local == "Relay" || remote == "Relay" {
            Self::Relayed
        } else if local == "Srflx" || remote == "Srflx" {
            Self::ServerReflexiveDirect
        } else if local == "Host" && remote == "Host" {
            Self::HostDirect
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub ice_mode: IceMode,
    pub ice_servers: Vec<IceServerConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum StatusMessage {
    Ping { id: String, sent_at: u64 },
    Pong { id: String, received_at: u64 },
    Status { version: u8 },
}

#[derive(Default)]
pub struct ReplayGuard {
    expiry_by_nonce: HashMap<String, u64>,
    order: VecDeque<String>,
}

fn encode_field(value: &[u8], output: &mut Vec<u8>) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| AgentError::InvalidSessionEnvelope)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_locator(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn validate_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn new_session_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AgentError::InvalidSessionEnvelope)?;
    if bytes.len() != length || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(AgentError::InvalidSessionEnvelope);
    }
    Ok(bytes)
}

impl SessionEnvelope {
    pub fn signed(
        identity: &DeviceIdentity,
        destination: PeerReference,
        kind: SessionKind,
        body: &[u8],
        now: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::signed_with_session_id(
            identity,
            destination,
            new_session_id(),
            kind,
            body,
            now,
            expires_at,
        )
    }

    pub fn signed_response(
        identity: &DeviceIdentity,
        destination: PeerReference,
        session_id: String,
        kind: SessionKind,
        body: &[u8],
        now: u64,
        expires_at: u64,
    ) -> Result<Self> {
        Self::signed_with_session_id(
            identity,
            destination,
            session_id,
            kind,
            body,
            now,
            expires_at,
        )
    }

    fn signed_with_session_id(
        identity: &DeviceIdentity,
        destination: PeerReference,
        session_id: String,
        kind: SessionKind,
        body: &[u8],
        now: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let source = PeerReference {
            locator: identity.public.locator.clone(),
            fingerprint: identity.public.fingerprint.clone(),
        };
        let mut envelope = Self {
            version: 1,
            session_id,
            nonce: new_session_id(),
            kind,
            created_at: now,
            expires_at,
            source,
            destination,
            body: URL_SAFE_NO_PAD.encode(body),
            signature: String::new(),
        };
        envelope.validate_shape_without_signature()?;
        envelope.signature = URL_SAFE_NO_PAD.encode(identity.sign(&envelope.payload()?));
        Ok(envelope)
    }

    pub fn payload(&self) -> Result<Vec<u8>> {
        self.validate_shape_without_signature()?;
        let body = URL_SAFE_NO_PAD
            .decode(&self.body)
            .map_err(|_| AgentError::InvalidSessionEnvelope)?;
        let mut output = Vec::with_capacity(SESSION_DOMAIN.len() + body.len() + 512);
        output.extend_from_slice(SESSION_DOMAIN);
        output.push(self.version);
        for field in [
            self.session_id.as_bytes(),
            self.nonce.as_bytes(),
            self.kind.as_str().as_bytes(),
            self.source.locator.as_bytes(),
            self.source.fingerprint.as_bytes(),
            self.destination.locator.as_bytes(),
            self.destination.fingerprint.as_bytes(),
        ] {
            encode_field(field, &mut output)?;
        }
        output.extend_from_slice(&self.created_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        encode_field(&body, &mut output)?;
        Ok(output)
    }

    fn validate_shape_without_signature(&self) -> Result<()> {
        if self.version != 1
            || !validate_locator(&self.source.locator)
            || !validate_locator(&self.destination.locator)
            || !validate_fingerprint(&self.source.fingerprint)
            || !validate_fingerprint(&self.destination.fingerprint)
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_SESSION_LIFETIME_MS
        {
            return Err(AgentError::InvalidSessionEnvelope);
        }
        decode_exact(&self.session_id, 16)?;
        decode_exact(&self.nonce, 16)?;
        let body = URL_SAFE_NO_PAD
            .decode(&self.body)
            .map_err(|_| AgentError::InvalidSessionEnvelope)?;
        if body.len() > MAX_SIGNAL_BODY_BYTES || URL_SAFE_NO_PAD.encode(&body) != self.body {
            return Err(AgentError::InvalidSessionEnvelope);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        self.validate_shape_without_signature()?;
        decode_exact(&self.signature, 64)?;
        Ok(())
    }

    pub fn verify_for(
        &self,
        identity: &DeviceIdentity,
        expected_peer: &AuthorizedSessionPeer,
        now: u64,
        replay_guard: &mut ReplayGuard,
    ) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let expected_peer = expected_peer.peer();
        if self.source.locator != expected_peer.locator
            || self.source.fingerprint != expected_peer.fingerprint
            || self.destination.locator != identity.public.locator
            || self.destination.fingerprint != identity.public.fingerprint
            || now.saturating_add(CLOCK_SKEW_MS) < self.created_at
            || now >= self.expires_at
        {
            return Err(AgentError::SessionIdentityOrFreshnessDenied);
        }
        if !verify_signature(
            &expected_peer.signing_public_key,
            &self.payload()?,
            &self.signature,
        )? {
            return Err(AgentError::SessionIdentityOrFreshnessDenied);
        }
        replay_guard.accept(&self.nonce, self.expires_at, now)?;
        URL_SAFE_NO_PAD
            .decode(&self.body)
            .map_err(|_| AgentError::InvalidSessionEnvelope)
    }
}

pub fn signed_description(
    identity: &DeviceIdentity,
    destination: PeerReference,
    session_id: Option<String>,
    kind: SessionKind,
    description: &RTCSessionDescription,
    now: u64,
    expires_at: u64,
) -> Result<SessionEnvelope> {
    let body = serde_json::to_vec(description).map_err(|_| AgentError::InvalidSessionEnvelope)?;
    match session_id {
        Some(session_id) => SessionEnvelope::signed_response(
            identity,
            destination,
            session_id,
            kind,
            &body,
            now,
            expires_at,
        ),
        None => SessionEnvelope::signed(identity, destination, kind, &body, now, expires_at),
    }
}

pub async fn accept_signed_description<P>(
    peer_connection: &P,
    envelope: &SessionEnvelope,
    expected_kind: SessionKind,
    expected_session_id: Option<&str>,
    identity: &DeviceIdentity,
    expected_peer: &AuthorizedSessionPeer,
    now: u64,
    replay_guard: &mut ReplayGuard,
) -> Result<RTCSessionDescription>
where
    P: PeerConnection,
{
    if envelope.kind != expected_kind
        || expected_session_id.is_some_and(|session_id| envelope.session_id != session_id)
    {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    let body = envelope.verify_for(identity, expected_peer, now, replay_guard)?;
    let description: RTCSessionDescription =
        serde_json::from_slice(&body).map_err(|_| AgentError::InvalidSessionEnvelope)?;
    peer_connection
        .set_remote_description(description.clone())
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    Ok(description)
}

impl ReplayGuard {
    pub fn accept(&mut self, nonce: &str, expires_at: u64, now: u64) -> Result<()> {
        while let Some(oldest) = self.order.front().cloned() {
            if self
                .expiry_by_nonce
                .get(&oldest)
                .is_some_and(|expiry| *expiry > now)
                && self.order.len() <= MAX_REPLAY_ENTRIES
            {
                break;
            }
            self.order.pop_front();
            self.expiry_by_nonce.remove(&oldest);
        }
        if self.expiry_by_nonce.contains_key(nonce) {
            return Err(AgentError::SessionReplayDenied);
        }
        self.expiry_by_nonce.insert(nonce.to_owned(), expires_at);
        self.order.push_back(nonce.to_owned());
        Ok(())
    }
}

pub fn decode_status_message(bytes: &[u8]) -> Result<StatusMessage> {
    if bytes.is_empty() || bytes.len() > MAX_STATUS_MESSAGE_BYTES {
        return Err(AgentError::InvalidStatusMessage);
    }
    serde_json::from_slice(bytes).map_err(|_| AgentError::InvalidStatusMessage)
}

pub fn encode_status_message(message: &StatusMessage) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(message).map_err(|_| AgentError::InvalidStatusMessage)?;
    if bytes.len() > MAX_STATUS_MESSAGE_BYTES {
        return Err(AgentError::InvalidStatusMessage);
    }
    Ok(bytes)
}

pub fn rtc_configuration(config: &TransportConfig) -> RTCConfiguration {
    let ice_servers = config
        .ice_servers
        .iter()
        .map(|server| RTCIceServer {
            urls: server.urls.clone(),
            username: server.username.clone().unwrap_or_default(),
            credential: server.credential.clone().unwrap_or_default(),
        })
        .collect();
    RTCConfigurationBuilder::new()
        .with_ice_servers(ice_servers)
        .with_ice_transport_policy(match config.ice_mode {
            IceMode::Automatic => RTCIceTransportPolicy::All,
            IceMode::RelayOnlyDiagnostic => RTCIceTransportPolicy::Relay,
        })
        .build()
}

pub async fn build_status_peer_connection<H>(
    config: &TransportConfig,
    handler: H,
    bind_address: String,
) -> Result<impl PeerConnection>
where
    H: PeerConnectionEventHandler,
{
    build_peer_connection(config, handler, bind_address, STATUS_SEND_BUFFER_BYTES).await
}

/// Build an authenticated WebRTC peer connection with an explicit application
/// send bound. Status uses 16 KiB; desktop uses a larger but still finite
/// buffer for one bounded JPEG frame and ordered input messages.
pub async fn build_peer_connection<H>(
    config: &TransportConfig,
    handler: H,
    bind_address: String,
    data_channel_send_buffer_bytes: usize,
) -> Result<impl PeerConnection>
where
    H: PeerConnectionEventHandler,
{
    PeerConnectionBuilder::new()
        .with_configuration(rtc_configuration(config))
        .with_handler(Arc::new(handler))
        .with_runtime(Arc::new(TokioRuntime) as Arc<dyn Runtime>)
        .with_udp_addrs(vec![bind_address])
        .with_data_channel_send_buffer_limit(data_channel_send_buffer_bytes)
        .build()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use webrtc::data_channel::{DataChannel, DataChannelEvent};
    use webrtc::error::Error as WebRtcError;
    use webrtc::peer_connection::RTCIceGatheringState;

    use super::*;
    use crate::store::TrustedPeer;

    #[derive(Clone)]
    struct TestHandler {
        gathered: mpsc::Sender<()>,
        channel: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
    }

    #[async_trait::async_trait]
    impl PeerConnectionEventHandler for TestHandler {
        async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
            if state == RTCIceGatheringState::Complete {
                let _ = self.gathered.try_send(());
            }
        }

        async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
            if let Some(sender) = &self.channel {
                let _ = sender.try_send(channel);
            }
        }
    }

    fn peer(identity: &DeviceIdentity) -> TrustedPeer {
        TrustedPeer {
            locator: identity.public.locator.clone(),
            fingerprint: identity.public.fingerprint.clone(),
            signing_public_key: identity.public.signing_public_key.clone(),
            noise_public_key: identity.public.noise_public_key.clone(),
            display_name: "test peer".into(),
        }
    }

    fn authorized_peer(identity: &DeviceIdentity) -> AuthorizedSessionPeer {
        AuthorizedSessionPeer::for_test(peer(identity))
    }

    #[test]
    fn signed_envelope_rejects_identity_substitution_replay_expiry_and_large_bodies() {
        let host = DeviceIdentity::generate(1).expect("host identity");
        let controller = DeviceIdentity::generate(2).expect("controller identity");
        let destination = PeerReference {
            locator: host.public.locator.clone(),
            fingerprint: host.public.fingerprint.clone(),
        };
        let message = SessionEnvelope::signed(
            &controller,
            destination,
            SessionKind::Offer,
            b"bounded-sdp",
            1_000,
            2_000,
        )
        .expect("signed offer");
        let mut replay_guard = ReplayGuard::default();
        assert_eq!(
            message
                .verify_for(
                    &host,
                    &authorized_peer(&controller),
                    1_001,
                    &mut replay_guard
                )
                .expect("valid signed offer"),
            b"bounded-sdp"
        );
        assert!(matches!(
            message.verify_for(
                &host,
                &authorized_peer(&controller),
                1_001,
                &mut replay_guard
            ),
            Err(AgentError::SessionReplayDenied)
        ));
        let mut incorrect_peer = peer(&controller);
        incorrect_peer.fingerprint = "a".repeat(64);
        assert!(matches!(
            message.verify_for(
                &host,
                &AuthorizedSessionPeer::for_test(incorrect_peer),
                1_001,
                &mut ReplayGuard::default()
            ),
            Err(AgentError::SessionIdentityOrFreshnessDenied)
        ));
        assert!(matches!(
            message.verify_for(
                &host,
                &authorized_peer(&controller),
                2_000,
                &mut ReplayGuard::default()
            ),
            Err(AgentError::SessionIdentityOrFreshnessDenied)
        ));
        assert!(SessionEnvelope::signed(
            &controller,
            PeerReference {
                locator: host.public.locator.clone(),
                fingerprint: host.public.fingerprint.clone()
            },
            SessionKind::Offer,
            &vec![0_u8; MAX_SIGNAL_BODY_BYTES + 1],
            1_000,
            2_000,
        )
        .is_err());
    }

    #[test]
    fn status_wire_rejects_malformed_and_oversize_messages() {
        assert!(decode_status_message(b"{\"type\":\"exec\",\"command\":\"id\"}").is_err());
        assert!(decode_status_message(&vec![b'x'; MAX_STATUS_MESSAGE_BYTES + 1]).is_err());
        let encoded = encode_status_message(&StatusMessage::Ping {
            id: "nonce".into(),
            sent_at: 1,
        })
        .expect("bounded ping");
        assert!(matches!(
            decode_status_message(&encoded),
            Ok(StatusMessage::Ping { .. })
        ));
    }

    #[test]
    fn route_labels_come_from_selected_candidate_types_not_ice_configuration() {
        assert_eq!(
            SelectedRoute::from_candidate_types("Host", "Host"),
            SelectedRoute::HostDirect
        );
        assert_eq!(
            SelectedRoute::from_candidate_types("Srflx", "Host"),
            SelectedRoute::ServerReflexiveDirect
        );
        assert_eq!(
            SelectedRoute::from_candidate_types("Relay", "Relay"),
            SelectedRoute::Relayed
        );
        assert_eq!(
            SelectedRoute::from_candidate_types("Prflx", "Host"),
            SelectedRoute::Unknown
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_real_local_webrtc_peers_exchange_a_bounded_status_ping() {
        let automatic = TransportConfig {
            ice_mode: IceMode::Automatic,
            ice_servers: vec![],
        };
        let host_identity = DeviceIdentity::generate(10).expect("host identity");
        let controller_identity = DeviceIdentity::generate(11).expect("controller identity");
        let host_reference = PeerReference {
            locator: host_identity.public.locator.clone(),
            fingerprint: host_identity.public.fingerprint.clone(),
        };
        let controller_reference = PeerReference {
            locator: controller_identity.public.locator.clone(),
            fingerprint: controller_identity.public.fingerprint.clone(),
        };
        let mut host_replay_guard = ReplayGuard::default();
        let mut controller_replay_guard = ReplayGuard::default();
        let (offer_gathered_tx, mut offer_gathered_rx) = mpsc::channel(1);
        let (answer_gathered_tx, mut answer_gathered_rx) = mpsc::channel(1);
        let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
        let offer = build_status_peer_connection(
            &automatic,
            TestHandler {
                gathered: offer_gathered_tx,
                channel: None,
            },
            "127.0.0.1:0".into(),
        )
        .await
        .expect("offer peer connection");
        let answer = build_status_peer_connection(
            &automatic,
            TestHandler {
                gathered: answer_gathered_tx,
                channel: Some(incoming_tx),
            },
            "127.0.0.1:0".into(),
        )
        .await
        .expect("answer peer connection");
        let data_channel = offer
            .create_data_channel("wii-status-v1", None)
            .await
            .expect("create bounded data channel");

        let offer_description = offer.create_offer(None).await.expect("offer SDP");
        offer
            .set_local_description(offer_description)
            .await
            .expect("set local offer");
        timeout(Duration::from_secs(5), offer_gathered_rx.recv())
            .await
            .expect("offer gathers candidates")
            .expect("offer gather event");
        let signed_offer = signed_description(
            &controller_identity,
            host_reference,
            None,
            SessionKind::Offer,
            &offer.local_description().await.expect("local offer"),
            1_000,
            61_000,
        )
        .expect("signed offer SDP");
        accept_signed_description(
            &answer,
            &signed_offer,
            SessionKind::Offer,
            None,
            &host_identity,
            &authorized_peer(&controller_identity),
            1_001,
            &mut host_replay_guard,
        )
        .await
        .expect("verify and set signed remote offer");
        let answer_description = answer.create_answer(None).await.expect("answer SDP");
        answer
            .set_local_description(answer_description)
            .await
            .expect("set local answer");
        timeout(Duration::from_secs(5), answer_gathered_rx.recv())
            .await
            .expect("answer gathers candidates")
            .expect("answer gather event");
        let signed_answer = signed_description(
            &host_identity,
            controller_reference,
            Some(signed_offer.session_id.clone()),
            SessionKind::Answer,
            &answer.local_description().await.expect("local answer"),
            1_002,
            61_000,
        )
        .expect("signed answer SDP");
        accept_signed_description(
            &offer,
            &signed_answer,
            SessionKind::Answer,
            Some(&signed_offer.session_id),
            &controller_identity,
            &authorized_peer(&host_identity),
            1_003,
            &mut controller_replay_guard,
        )
        .await
        .expect("verify and set signed remote answer");

        let remote_channel = timeout(Duration::from_secs(5), incoming_rx.recv())
            .await
            .expect("answer receives data channel")
            .expect("data channel event");
        timeout(Duration::from_secs(5), async {
            while let Some(event) = data_channel.poll().await {
                if matches!(event, DataChannelEvent::OnOpen) {
                    return;
                }
            }
        })
        .await
        .expect("data channel opens");
        let ping = encode_status_message(&StatusMessage::Ping {
            id: "local-ping".into(),
            sent_at: 1,
        })
        .expect("encode ping");
        let sender_channel = Arc::clone(&data_channel);
        let sender = tokio::spawn(async move {
            sender_channel
                .try_send_text(std::str::from_utf8(&ping).expect("utf8 ping"))
                .await
        });
        let received = timeout(Duration::from_secs(5), async {
            while let Some(event) = remote_channel.poll().await {
                if let DataChannelEvent::OnMessage(message) = event {
                    if matches!(
                        decode_status_message(&message.data),
                        Ok(StatusMessage::Ping { .. })
                    ) {
                        return message.data.to_vec();
                    }
                }
            }
            Vec::new()
        })
        .await
        .expect("status ping receives before timeout");
        sender
            .await
            .expect("sender task joins")
            .expect("bounded send succeeds");
        assert!(
            matches!(decode_status_message(&received), Ok(StatusMessage::Ping { id, .. }) if id == "local-ping")
        );
        // Do not rely on a configuration claim for backpressure: after the
        // receiver has stopped reading, the actual 16 KiB channel limit must
        // reject a burst before memory can grow unbounded.
        let oversized_burst = "x".repeat(MAX_STATUS_MESSAGE_BYTES);
        let mut queue_exhausted = false;
        for _ in 0..128 {
            match data_channel.try_send_text(&oversized_burst).await {
                Err(WebRtcError::ErrSendBufferFull) => {
                    queue_exhausted = true;
                    break;
                }
                Ok(()) => {}
                Err(error) => panic!("unexpected data-channel send error: {error}"),
            }
        }
        assert!(queue_exhausted, "bounded send queue rejects a burst");
        let selected_pair = offer
            .sctp()
            .await
            .expect("SCTP is negotiated")
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .await
            .expect("selected pair inspection")
            .expect("direct ICE selected a candidate pair");
        eprintln!(
            "selected ICE route evidence: local={:?}, remote={:?}",
            selected_pair.local().typ,
            selected_pair.remote().typ
        );
        assert_eq!(
            SelectedRoute::from_candidate_types(
                &format!("{:?}", selected_pair.local().typ),
                &format!("{:?}", selected_pair.remote().typ)
            ),
            SelectedRoute::HostDirect
        );
        offer.close().await.expect("offer closes");
        answer.close().await.expect("answer closes");
    }
}
