//! Authenticated native-agent connection to the coordination service.
//!
//! The client does not accept a client-provided authenticated flag.  Each new
//! WebSocket connection repeats the Phase 2A Ed25519 challenge response, and
//! WSS is always certificate-validated by rustls.  Plain WS is accepted only
//! for an explicit loopback development coordinator.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::identity::{auth_proof_payload, DeviceIdentity};
use crate::transport::{PeerReference, SessionEnvelope, SessionKind};
use crate::{AgentError, Result};

pub const AUTHENTICATION_TIMEOUT_MS: u64 = 10_000;
pub const TURN_CREDENTIAL_TTL_MS: u64 = 5 * 60_000;
pub const MAX_RECONNECT_ATTEMPTS: u8 = 3;

type CoordinatorSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthChallenge {
    #[serde(rename = "type")]
    message_type: String,
    connection_id: String,
    nonce: String,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthOk {
    #[serde(rename = "type")]
    message_type: String,
    locator: String,
    fingerprint: String,
    session_expires_at: u64,
    registration: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TurnIceServer {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TurnCredentials {
    #[serde(rename = "type")]
    message_type: String,
    pub session_id: String,
    pub expires_at: u64,
    pub ice_servers: Vec<TurnIceServer>,
}

pub struct AuthenticatedCoordinator {
    socket: CoordinatorSocket,
    pub session_expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
    pub maximum_backoff_ms: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_RECONNECT_ATTEMPTS,
            initial_backoff_ms: 250,
            maximum_backoff_ms: 2_000,
        }
    }
}

impl ReconnectPolicy {
    pub(crate) fn delay_before_attempt(&self, failed_attempts: u8) -> u64 {
        let multiplier = 1_u64 << u32::from(failed_attempts.saturating_sub(1).min(8));
        self.initial_backoff_ms
            .saturating_mul(multiplier)
            .min(self.maximum_backoff_ms)
    }
}

fn now_millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::CoordinatorProtocol("system clock is before Unix epoch".into()))
        .and_then(|duration| {
            u64::try_from(duration.as_millis())
                .map_err(|_| AgentError::CoordinatorProtocol("system clock is out of range".into()))
        })
}

fn validate_coordinator_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|_| AgentError::CoordinatorProtocol("invalid coordinator URL".into()))?;
    if url.path() != "/v1/connect" || url.query().is_some() || url.fragment().is_some() {
        return Err(AgentError::CoordinatorProtocol(
            "unexpected coordinator endpoint".into(),
        ));
    }
    match url.scheme() {
        "wss" => Ok(url),
        "ws" if matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        ) =>
        {
            Ok(url)
        }
        "ws" => Err(AgentError::CoordinatorProtocol(
            "plain WebSocket is allowed only for a loopback development coordinator".into(),
        )),
        _ => Err(AgentError::CoordinatorProtocol(
            "coordinator must use wss".into(),
        )),
    }
}

async fn send_value(socket: &mut CoordinatorSocket, value: Value) -> Result<()> {
    let text = serde_json::to_string(&value).map_err(|_| {
        AgentError::CoordinatorProtocol("could not serialize coordinator message".into())
    })?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|error| AgentError::CoordinatorProtocol(error.to_string()))
}

async fn receive_value(socket: &mut CoordinatorSocket) -> Result<Value> {
    let Some(message) = socket.next().await else {
        return Err(AgentError::CoordinatorProtocol(
            "coordinator closed connection".into(),
        ));
    };
    match message.map_err(|error| AgentError::CoordinatorProtocol(error.to_string()))? {
        Message::Text(text) => serde_json::from_str(&text)
            .map_err(|_| AgentError::CoordinatorProtocol("invalid coordinator JSON".into())),
        Message::Close(_) => Err(AgentError::CoordinatorProtocol(
            "coordinator closed connection".into(),
        )),
        _ => Err(AgentError::CoordinatorProtocol(
            "coordinator sent unexpected binary/control message".into(),
        )),
    }
}

fn coordinator_error(value: Value) -> Result<Value> {
    if let Some(code) = error_code(&value) {
        return Err(AgentError::CoordinatorDenied(code.into()));
    }
    Ok(value)
}

fn error_code(value: &Value) -> Option<&str> {
    value
        .as_object()?
        .get("type")?
        .as_str()
        .filter(|message_type| *message_type == "ERROR")
        .and_then(|_| value.as_object()?.get("code")?.as_str())
}

impl AuthenticatedCoordinator {
    /// Authenticate a new native-agent connection. Call this again after any
    /// disconnect rather than reusing a prior server-side session.
    pub async fn connect(url: &str, identity: &DeviceIdentity) -> Result<Self> {
        let url = validate_coordinator_url(url)?;
        let (mut socket, _) = tokio::time::timeout(
            std::time::Duration::from_millis(AUTHENTICATION_TIMEOUT_MS),
            connect_async(url.as_str()),
        )
        .await
        .map_err(|_| AgentError::CoordinatorProtocol("coordinator connection timed out".into()))?
        .map_err(|error| AgentError::CoordinatorProtocol(error.to_string()))?;
        let bundle = identity.identity_bundle()?;
        send_value(
            &mut socket,
            json!({ "type": "AUTH_BEGIN", "bundle": bundle }),
        )
        .await?;
        let challenge_value = tokio::time::timeout(
            std::time::Duration::from_millis(AUTHENTICATION_TIMEOUT_MS),
            receive_value(&mut socket),
        )
        .await
        .map_err(|_| {
            AgentError::CoordinatorProtocol("coordinator authentication challenge timed out".into())
        })??;
        if let Some(code) = error_code(&challenge_value) {
            return Err(AgentError::CoordinatorDenied(code.into()));
        }
        let challenge: AuthChallenge = serde_json::from_value(challenge_value).map_err(|_| {
            AgentError::CoordinatorProtocol("malformed authentication challenge".into())
        })?;
        if challenge.message_type != "AUTH_CHALLENGE" || now_millis()? > challenge.expires_at {
            return Err(AgentError::CoordinatorProtocol(
                "expired or unexpected authentication challenge".into(),
            ));
        }
        let proof = identity.sign(&auth_proof_payload(
            &challenge.connection_id,
            &challenge.nonce,
            &identity.public.locator,
            &identity.public.fingerprint,
            challenge.expires_at,
        )?);
        send_value(
            &mut socket,
            json!({
                "type": "AUTH_PROVE",
                "connectionId": challenge.connection_id,
                "nonce": challenge.nonce,
                "expiresAt": challenge.expires_at,
                "signature": URL_SAFE_NO_PAD.encode(proof)
            }),
        )
        .await?;
        let authenticated_value = tokio::time::timeout(
            std::time::Duration::from_millis(AUTHENTICATION_TIMEOUT_MS),
            receive_value(&mut socket),
        )
        .await
        .map_err(|_| {
            AgentError::CoordinatorProtocol("coordinator authentication result timed out".into())
        })??;
        if let Some(code) = error_code(&authenticated_value) {
            return Err(AgentError::CoordinatorDenied(code.into()));
        }
        let authenticated: AuthOk = serde_json::from_value(authenticated_value).map_err(|_| {
            AgentError::CoordinatorProtocol("malformed authentication result".into())
        })?;
        if authenticated.message_type != "AUTH_OK"
            || authenticated.locator != identity.public.locator
            || authenticated.fingerprint != identity.public.fingerprint
            || authenticated.session_expires_at <= now_millis()?
            || !matches!(authenticated.registration.as_str(), "created" | "existing")
        {
            return Err(AgentError::CoordinatorProtocol(
                "coordinator identity result mismatch".into(),
            ));
        }
        Ok(Self {
            socket,
            session_expires_at: authenticated.session_expires_at,
        })
    }

    /// Retry only a fresh authenticated connection. It never reuses a nonce,
    /// proof, session expiry, or TURN credential from a disconnected socket.
    pub async fn connect_with_retry(
        url: &str,
        identity: &DeviceIdentity,
        policy: &ReconnectPolicy,
    ) -> Result<Self> {
        if policy.max_attempts == 0
            || policy.initial_backoff_ms == 0
            || policy.maximum_backoff_ms == 0
        {
            return Err(AgentError::CoordinatorProtocol(
                "invalid reconnect policy".into(),
            ));
        }
        let mut last_error = None;
        for attempt in 1..=policy.max_attempts {
            match Self::connect(url, identity).await {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            }
            if attempt < policy.max_attempts {
                tokio::time::sleep(std::time::Duration::from_millis(
                    policy.delay_before_attempt(attempt),
                ))
                .await;
            }
        }
        Err(last_error
            .unwrap_or_else(|| AgentError::CoordinatorProtocol("reconnect failed".into())))
    }

    pub fn session_is_current(&self, now: u64) -> bool {
        now < self.session_expires_at
    }

    /// Receive exactly one coordinator event.  A caller must serialise command
    /// response waits with event handling: a WebSocket has one ordered stream.
    pub(crate) async fn receive_message(&mut self, timeout_ms: u64) -> Result<Value> {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            receive_value(&mut self.socket),
        )
        .await
        .map_err(|_| AgentError::SessionTimedOut)?
        .and_then(coordinator_error)
    }

    pub(crate) async fn send_message(&mut self, value: Value) -> Result<()> {
        send_value(&mut self.socket, value).await
    }

    pub async fn relay_envelope(&mut self, envelope: &SessionEnvelope) -> Result<()> {
        let payload =
            serde_json::to_vec(envelope).map_err(|_| AgentError::InvalidSessionEnvelope)?;
        if payload.len() > crate::transport::MAX_SIGNAL_ENVELOPE_BYTES {
            return Err(AgentError::InvalidSessionEnvelope);
        }
        let kind = match envelope.kind {
            SessionKind::Offer => "webrtc.offer",
            SessionKind::Answer => "webrtc.answer",
            SessionKind::Cancel => "webrtc.cancel",
            SessionKind::IceCandidate => "webrtc.candidate",
            SessionKind::Revocation => "control.revocation",
            SessionKind::RevocationAck => "control.revocation-ack",
        };
        self.send_message(json!({
            "type": "SIGNAL",
            "destination": envelope.destination,
            "payload": { "kind": kind, "data": URL_SAFE_NO_PAD.encode(payload) }
        }))
        .await
    }

    pub async fn request_turn_credentials(
        &mut self,
        destination: &PeerReference,
        session_id: &str,
    ) -> Result<TurnCredentials> {
        if URL_SAFE_NO_PAD
            .decode(session_id)
            .map_or(true, |bytes| bytes.len() != 16)
        {
            return Err(AgentError::InvalidSessionEnvelope);
        }
        send_value(
            &mut self.socket,
            json!({
                "type": "TURN_CREDENTIAL_REQUEST",
                "capability": "desktop.view",
                "destination": destination,
                "sessionId": session_id,
                "ttlMs": TURN_CREDENTIAL_TTL_MS
            }),
        )
        .await?;
        let value = self.receive_message(AUTHENTICATION_TIMEOUT_MS).await?;
        let credentials: TurnCredentials = serde_json::from_value(value).map_err(|_| {
            AgentError::CoordinatorProtocol("malformed TURN credential response".into())
        })?;
        if credentials.message_type != "TURN_CREDENTIALS"
            || credentials.session_id != session_id
            || credentials.expires_at <= now_millis()?
            || credentials.ice_servers.is_empty()
            || credentials.ice_servers.iter().any(|server| {
                server.urls.is_empty()
                    || server
                        .urls
                        .iter()
                        .any(|url| !url.starts_with("turn:") && !url.starts_with("turns:"))
                    || server.username.is_empty()
                    || server.credential.is_empty()
            })
        {
            return Err(AgentError::CoordinatorProtocol(
                "invalid TURN credential response".into(),
            ));
        }
        Ok(credentials)
    }

    pub async fn close(mut self) -> Result<()> {
        self.socket
            .close(None)
            .await
            .map_err(|error| AgentError::CoordinatorProtocol(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_remote_and_wrong_path_coordinator_urls() {
        assert!(validate_coordinator_url("ws://example.com/v1/connect").is_err());
        assert!(validate_coordinator_url("wss://example.com/nope").is_err());
        assert!(validate_coordinator_url("ws://127.0.0.1:4310/v1/connect").is_ok());
        assert!(validate_coordinator_url("wss://coord.example/v1/connect").is_ok());
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        let policy = ReconnectPolicy::default();
        assert_eq!(policy.delay_before_attempt(1), 250);
        assert_eq!(policy.delay_before_attempt(2), 500);
        assert_eq!(policy.delay_before_attempt(3), 1_000);
        assert_eq!(policy.delay_before_attempt(99), 2_000);
    }
}
