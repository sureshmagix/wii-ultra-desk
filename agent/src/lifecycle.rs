//! Local control plane for the independently running native agent.
//!
//! This deliberately is not a TCP management API. On Unix it is a mode 0600
//! Unix-domain socket in the agent's mode 0700 state directory, and every
//! request is additionally checked against the connecting OS UID. The service
//! exposes only operational lifecycle controls; no private key, grant secret,
//! screen content, keyboard data, or arbitrary process command crosses it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::coordinator::AuthenticatedCoordinator;
use crate::store::{AgentStore, SecurityEvent, TrustedDeviceSummary, UnattendedStatus};
use crate::transport::{new_session_id, PeerReference, ReplayGuard, SessionEnvelope, SessionKind};
use crate::{AgentError, Result};

pub const LOCAL_CONTROL_SOCKET: &str = "agent-control.sock";
const MAX_CONTROL_LINE_BYTES: usize = 8 * 1024;
// macOS's `sockaddr_un` accepts fewer than 104 pathname bytes. Keep a margin
// below the smallest supported Unix limit so a deeply nested state directory
// cannot make the owner control plane disappear.
const MAX_DIRECT_SOCKET_PATH_BYTES: usize = 90;
const FALLBACK_CONTROL_DIRECTORY_PREFIX: &str = ".wud-control-";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "action", deny_unknown_fields)]
pub enum LocalControlRequest {
    Status { version: u8 },
    TrustedDevices { version: u8 },
    SecurityEvents { version: u8, limit: u32 },
    Disconnect { version: u8, confirmation: String },
    Disable { version: u8, confirmation: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalControlResponse {
    pub ok: bool,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<UnattendedStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_devices: Option<Vec<TrustedDeviceSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<SecurityEvent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevocationRequest {
    request_id: String,
    controller_fingerprint: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevocationAcknowledgement {
    request_id: String,
    revoked_controller_fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRevocationResult {
    pub request_id: String,
    pub state: String,
}

pub fn socket_path(state_dir: &Path) -> PathBuf {
    let direct = state_dir.join(LOCAL_CONTROL_SOCKET);
    if direct.to_string_lossy().as_bytes().len() <= MAX_DIRECT_SOCKET_PATH_BYTES {
        return direct;
    }
    // Do not use `temp_dir`: on macOS it is commonly itself deeply nested.
    // The daemon creates this deterministic, owner-only directory before
    // binding; the client only needs the same calculation to find the socket.
    let digest = Sha256::digest(state_dir.to_string_lossy().as_bytes());
    let suffix = URL_SAFE_NO_PAD.encode(&digest[..18]);
    PathBuf::from("/tmp")
        .join(format!("{FALLBACK_CONTROL_DIRECTORY_PREFIX}{suffix}"))
        .join(LOCAL_CONTROL_SOCKET)
}

fn now_millis() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AgentError::SessionAuthorizationDenied)
        .and_then(|value| {
            u64::try_from(value.as_millis()).map_err(|_| AgentError::SessionAuthorizationDenied)
        })
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn signal_envelope(value: Value) -> Result<SessionEnvelope> {
    let object = value
        .as_object()
        .ok_or_else(|| AgentError::CoordinatorProtocol("malformed lifecycle signal".into()))?;
    if object.get("type").and_then(Value::as_str) != Some("SIGNAL") {
        return Err(AgentError::CoordinatorProtocol(
            "unexpected lifecycle event".into(),
        ));
    }
    let source = object
        .get("source")
        .and_then(Value::as_object)
        .ok_or(AgentError::SessionIdentityOrFreshnessDenied)?;
    let data = object
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("data"))
        .and_then(Value::as_str)
        .ok_or(AgentError::InvalidSessionEnvelope)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| AgentError::InvalidSessionEnvelope)?;
    if bytes.is_empty()
        || bytes.len() > crate::transport::MAX_SIGNAL_ENVELOPE_BYTES
        || URL_SAFE_NO_PAD.encode(&bytes) != data
    {
        return Err(AgentError::InvalidSessionEnvelope);
    }
    let envelope: SessionEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| AgentError::InvalidSessionEnvelope)?;
    if source.get("locator").and_then(Value::as_str) != Some(envelope.source.locator.as_str())
        || source.get("fingerprint").and_then(Value::as_str)
            != Some(envelope.source.fingerprint.as_str())
    {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    Ok(envelope)
}

pub async fn request_remote_revocation(
    state_dir: PathBuf,
    coordinator_url: &str,
    host: PeerReference,
) -> Result<RemoteRevocationResult> {
    let mut store = AgentStore::open(state_dir)?;
    let identity = store.load_or_create_identity()?;
    let now = now_millis()?;
    let request_id = new_session_id();
    // Persist before sending: a coordinator receipt alone is not a host
    // acknowledgement, so interruption leaves a visible pending request.
    store.request_remote_revocation(&request_id, &host.fingerprint, now)?;
    let body = serde_json::to_vec(&RevocationRequest {
        request_id: request_id.clone(),
        controller_fingerprint: identity.public.fingerprint.clone(),
    })
    .map_err(|_| AgentError::InvalidSessionEnvelope)?;
    let envelope = SessionEnvelope::signed_response(
        &identity,
        host.clone(),
        request_id.clone(),
        SessionKind::Revocation,
        &body,
        now,
        now.saturating_add(60_000),
    )?;
    let mut coordinator = AuthenticatedCoordinator::connect(coordinator_url, &identity).await?;
    coordinator.relay_envelope(&envelope).await?;
    let mut replay = ReplayGuard::default();
    loop {
        let incoming = coordinator.receive_message(25_000).await?;
        let envelope = match signal_envelope(incoming) {
            Ok(envelope) => envelope,
            Err(AgentError::CoordinatorProtocol(_)) => continue,
            Err(error) => return Err(error),
        };
        if envelope.kind != SessionKind::RevocationAck || envelope.session_id != request_id {
            continue;
        }
        let peer = store.trusted_session_peer(&host.locator, &host.fingerprint)?;
        let payload = envelope.verify_for(&identity, &peer, now_millis()?, &mut replay)?;
        let acknowledgement: RevocationAcknowledgement =
            serde_json::from_slice(&payload).map_err(|_| AgentError::InvalidSessionEnvelope)?;
        if acknowledgement.request_id != request_id
            || acknowledgement.revoked_controller_fingerprint != identity.public.fingerprint
        {
            return Err(AgentError::SessionIdentityOrFreshnessDenied);
        }
        store.acknowledge_remote_revocation(&request_id, &host.fingerprint, now_millis()?)?;
        return Ok(RemoteRevocationResult {
            request_id,
            state: "acknowledged".into(),
        });
    }
}

async fn listen_for_revocations(state_dir: PathBuf, coordinator_url: String) -> Result<()> {
    let mut store = AgentStore::open(state_dir)?;
    let identity = store.load_or_create_identity()?;
    let mut replay = ReplayGuard::default();
    loop {
        let mut coordinator =
            match AuthenticatedCoordinator::connect(&coordinator_url, &identity).await {
                Ok(connection) => connection,
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
        loop {
            let incoming = match coordinator.receive_message(30_000).await {
                Ok(value) => value,
                Err(_) => break,
            };
            let envelope = match signal_envelope(incoming) {
                Ok(envelope) if envelope.kind == SessionKind::Revocation => envelope,
                Ok(_) | Err(_) => continue,
            };
            let peer = match store
                .trusted_session_peer(&envelope.source.locator, &envelope.source.fingerprint)
            {
                Ok(peer) => peer,
                Err(_) => continue,
            };
            let payload = match envelope.verify_for(&identity, &peer, now_millis()?, &mut replay) {
                Ok(payload) => payload,
                Err(_) => continue,
            };
            let request: RevocationRequest =
                match serde_json::from_slice::<RevocationRequest>(&payload) {
                    Ok(request)
                        if valid_request_id(&request.request_id)
                            && request.request_id == envelope.session_id
                            && request.controller_fingerprint == envelope.source.fingerprint =>
                    {
                        request
                    }
                    _ => continue,
                };
            let now = now_millis()?;
            // Record before ending live channels. Repeated signed requests are
            // harmless: the first one makes the identity unusable, while an
            // acknowledgement remains tied to the exact request ID.
            let _ = store.request_remote_revocation(
                &request.request_id,
                &envelope.source.fingerprint,
                now,
            );
            if store
                .revoke_peer(&envelope.source.fingerprint, now)
                .is_err()
            {
                continue;
            }
            let _ = store.acknowledge_remote_revocation(
                &request.request_id,
                &envelope.source.fingerprint,
                now,
            );
            let body = serde_json::to_vec(&RevocationAcknowledgement {
                request_id: request.request_id.clone(),
                revoked_controller_fingerprint: envelope.source.fingerprint.clone(),
            })
            .map_err(|_| AgentError::InvalidSessionEnvelope)?;
            let acknowledgement = SessionEnvelope::signed_response(
                &identity,
                envelope.source,
                request.request_id,
                SessionKind::RevocationAck,
                &body,
                now,
                now.saturating_add(60_000),
            )?;
            let _ = coordinator.relay_envelope(&acknowledgement).await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn failure() -> LocalControlResponse {
    LocalControlResponse {
        ok: false,
        code: "request_rejected".into(),
        status: None,
        trusted_devices: None,
        events: None,
        disconnected: None,
    }
}

pub fn handle_local_request(
    store: &mut AgentStore,
    request: LocalControlRequest,
    now: u64,
) -> LocalControlResponse {
    let version = match &request {
        LocalControlRequest::Status { version }
        | LocalControlRequest::TrustedDevices { version }
        | LocalControlRequest::SecurityEvents { version, .. }
        | LocalControlRequest::Disconnect { version, .. }
        | LocalControlRequest::Disable { version, .. } => *version,
    };
    if version != 1 {
        return failure();
    }
    let result = match request {
        LocalControlRequest::Status { .. } => {
            store
                .unattended_status()
                .map(|status| LocalControlResponse {
                    ok: true,
                    code: "ok".into(),
                    status: Some(status),
                    trusted_devices: None,
                    events: None,
                    disconnected: None,
                })
        }
        LocalControlRequest::TrustedDevices { .. } => {
            store
                .trusted_devices()
                .map(|trusted_devices| LocalControlResponse {
                    ok: true,
                    code: "ok".into(),
                    status: None,
                    trusted_devices: Some(trusted_devices),
                    events: None,
                    disconnected: None,
                })
        }
        LocalControlRequest::SecurityEvents { limit, .. } => {
            store
                .security_events(limit)
                .map(|events| LocalControlResponse {
                    ok: true,
                    code: "ok".into(),
                    status: None,
                    trusted_devices: None,
                    events: Some(events),
                    disconnected: None,
                })
        }
        LocalControlRequest::Disconnect { confirmation, .. }
            if confirmation == "disconnect_unattended" =>
        {
            store
                .disconnect_unattended_sessions(now, "local_disconnect")
                .and_then(|disconnected| {
                    store
                        .unattended_status()
                        .map(|status| LocalControlResponse {
                            ok: true,
                            code: "ok".into(),
                            status: Some(status),
                            trusted_devices: None,
                            events: None,
                            disconnected: Some(disconnected),
                        })
                })
        }
        LocalControlRequest::Disable { confirmation, .. }
            if confirmation == "disable_unattended" =>
        {
            store
                .disable_unattended(now, "local_owner_disabled")
                .and_then(|_| {
                    store
                        .unattended_status()
                        .map(|status| LocalControlResponse {
                            ok: true,
                            code: "ok".into(),
                            status: Some(status),
                            trusted_devices: None,
                            events: None,
                            disconnected: None,
                        })
                })
        }
        _ => Err(AgentError::SessionAuthorizationDenied),
    };
    result.unwrap_or_else(|_| failure())
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::*;

    fn fallback_control_directory(path: &Path) -> bool {
        path.parent().is_some_and(|parent| {
            parent.parent() == Some(Path::new("/tmp"))
                && parent
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(FALLBACK_CONTROL_DIRECTORY_PREFIX))
        })
    }

    fn prepare_fallback_control_directory(path: &Path) -> Result<()> {
        if !fallback_control_directory(path) {
            return Ok(());
        }
        let directory = path
            .parent()
            .ok_or(AgentError::SessionAuthorizationDenied)?;
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        // This can repair only an owner-owned directory. A different owner or
        // a symlink was rejected above, so no shared /tmp object is trusted.
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn remove_previous_socket(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.uid() == unsafe { libc::geteuid() } =>
            {
                fs::remove_file(path)?;
                Ok(())
            }
            Ok(_) => Err(AgentError::SessionAuthorizationDenied),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn peer_is_owner(stream: &UnixStream) -> bool {
        let fd = stream.as_raw_fd();
        #[cfg(target_os = "macos")]
        {
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            // SAFETY: the stream has a valid Unix socket descriptor and the
            // pointers refer to initialized local uid/gid storage.
            return unsafe {
                libc::getpeereid(fd, &mut uid, &mut gid) == 0 && uid == libc::geteuid()
            };
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: the descriptor is a Unix stream socket, and the buffer
            // and length are valid for SO_PEERCRED.
            return unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut credentials as *mut _ as *mut libc::c_void,
                    &mut length,
                ) == 0
                    && credentials.uid == libc::geteuid()
            };
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
        {
            false
        }
    }

    async fn serve_one(stream: UnixStream, state_dir: PathBuf) -> io::Result<()> {
        if !peer_is_owner(&stream) {
            return Ok(());
        }
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let line = match lines.next_line().await? {
            Some(line) if line.len() <= MAX_CONTROL_LINE_BYTES => line,
            _ => return Ok(()),
        };
        let response = match serde_json::from_str::<LocalControlRequest>(&line) {
            Ok(request) => match AgentStore::open(state_dir) {
                Ok(mut store) => {
                    handle_local_request(&mut store, request, now_millis().unwrap_or(0))
                }
                Err(_) => failure(),
            },
            Err(_) => failure(),
        };
        let body = serde_json::to_vec(&response)
            .unwrap_or_else(|_| b"{\"ok\":false,\"code\":\"request_rejected\"}".to_vec());
        writer.write_all(&body).await?;
        writer.write_all(b"\n").await
    }

    pub async fn run_local_control_server(state_dir: PathBuf) -> Result<()> {
        let path = socket_path(&state_dir);
        prepare_fallback_control_directory(&path)?;
        remove_previous_socket(&path)?;
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        loop {
            let (stream, _) = listener.accept().await?;
            // Requests are intentionally serialized. The SQLite database is
            // the source of truth, and this keeps owner actions ordered.
            let _ = serve_one(stream, state_dir.clone()).await;
        }
    }

    pub async fn local_control_client(
        state_dir: PathBuf,
        request: LocalControlRequest,
    ) -> Result<LocalControlResponse> {
        let mut stream = UnixStream::connect(socket_path(&state_dir)).await?;
        let body =
            serde_json::to_vec(&request).map_err(|_| AgentError::SessionAuthorizationDenied)?;
        if body.len() > MAX_CONTROL_LINE_BYTES {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        stream.write_all(&body).await?;
        stream.write_all(b"\n").await?;
        let mut lines = BufReader::new(stream).lines();
        let line = lines
            .next_line()
            .await?
            .ok_or(AgentError::SessionAuthorizationDenied)?;
        if line.len() > MAX_CONTROL_LINE_BYTES {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        serde_json::from_str(&line).map_err(|_| AgentError::SessionAuthorizationDenied)
    }
}

#[cfg(unix)]
pub use unix::{local_control_client, run_local_control_server};

#[cfg(not(unix))]
pub async fn run_local_control_server(_state_dir: PathBuf) -> Result<()> {
    Err(AgentError::UnattendedAccessDisabled)
}

#[cfg(not(unix))]
pub async fn local_control_client(
    _state_dir: PathBuf,
    _request: LocalControlRequest,
) -> Result<LocalControlResponse> {
    Err(AgentError::UnattendedAccessDisabled)
}

/// The daemon keeps local lifecycle control available even when Electron is
/// closed. Supplying a coordinator adds only signed revocation listening; it
/// does not create a generic remote-command listener.
pub async fn run_daemon(state_dir: PathBuf, coordinator_url: Option<String>) -> Result<()> {
    match coordinator_url {
        Some(url) => tokio::select! {
            result = run_local_control_server(state_dir.clone()) => result,
            result = listen_for_revocations(state_dir, url) => result,
        },
        None => run_local_control_server(state_dir).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::store::TrustedPeer;

    #[test]
    fn local_control_requires_exact_confirmation_and_stays_off_by_default() {
        let state =
            std::env::temp_dir().join(format!("wii-local-control-{}", now_millis().unwrap_or(1)));
        let peer_identity = DeviceIdentity::generate(2).expect("peer");
        let peer = TrustedPeer {
            locator: peer_identity.public.locator,
            fingerprint: peer_identity.public.fingerprint,
            signing_public_key: peer_identity.public.signing_public_key,
            noise_public_key: peer_identity.public.noise_public_key,
            display_name: "test peer".into(),
        };
        let mut store = AgentStore::open(&state).expect("store");
        store.persist_trusted_peer(&peer, 10).expect("peer");
        let status =
            handle_local_request(&mut store, LocalControlRequest::Status { version: 1 }, 10);
        assert!(status.ok);
        assert!(!status.status.expect("status").enabled);
        let rejected = handle_local_request(
            &mut store,
            LocalControlRequest::Disable {
                version: 1,
                confirmation: "no".into(),
            },
            10,
        );
        assert!(!rejected.ok);
        std::fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn deep_state_directories_use_a_short_deterministic_owner_socket_path() {
        let state = PathBuf::from("/a").join("very-deep-state-directory".repeat(10));
        let path = socket_path(&state);
        assert!(path.starts_with("/tmp"));
        assert!(path.to_string_lossy().as_bytes().len() <= MAX_DIRECT_SOCKET_PATH_BYTES);
        assert_eq!(path, socket_path(&state));
    }
}
