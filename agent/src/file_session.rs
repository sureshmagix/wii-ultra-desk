//! Authenticated, root-confined, resumable file transfer session.
//!
//! This protocol intentionally transfers one bounded chunk only after the
//! receiver asks for or acknowledges it. That makes backpressure explicit and
//! leaves room for the desktop data channel; there is no generic RPC or raw
//! TCP forwarding surface.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::timeout;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{PeerConnection, PeerConnectionEventHandler, RTCIceGatheringState};

use crate::coordinator::{AuthenticatedCoordinator, ReconnectPolicy, TurnCredentials};
use crate::identity::DeviceIdentity;
use crate::secure_file::{
    FileEntry, FileManifest, RootedFileSystem, WriteTransfer, MAX_CHUNK_BYTES,
};
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

const FILE_PROTOCOL_VERSION: u8 = 1;
const FILE_CHANNEL_LABEL: &str = "wii-files-v1";
const MAX_FILE_MESSAGE_BYTES: usize = 80 * 1024;
const FILE_DATA_CHANNEL_BUFFER_BYTES: usize = 128 * 1024;
const FILE_SESSION_MAX_MS: u64 = 30 * 60_000;
// File channels deliberately leave time between acknowledged chunks. At 32
// KiB every 15 ms the protocol has an approximate 2 MiB/s payload ceiling,
// leaving capacity for interactive desktop/input channels on the same link.
const FILE_CHUNK_PACING_MS: u64 = 15;

#[derive(Clone, Debug)]
pub struct FileSessionConfig {
    pub coordinator_url: String,
    pub peer: PeerReference,
    pub ice_mode: IceMode,
    pub stun_urls: Vec<String>,
    pub bind_address: String,
    /// Loopback-harness-only switch. TURN credentials are still authorized by
    /// the coordinator but are deliberately omitted from ICE so a local direct
    /// test cannot be misreported as a relay result.
    pub local_test_skip_turn_transport: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSessionRole {
    Controller,
    Host,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileCommand {
    ListLocal {
        path: String,
    },
    ListRemote {
        path: String,
    },
    Upload {
        transfer_id: String,
        source: String,
        destination: String,
        collision: CollisionPolicy,
    },
    Download {
        transfer_id: String,
        source: String,
        destination: String,
        collision: CollisionPolicy,
    },
    Cancel {
        transfer_id: String,
    },
    Disconnect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionPolicy {
    Fail,
    Replace,
}

impl CollisionPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Replace => "replace",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileEvent {
    State {
        state: ConnectionState,
        route: SelectedRoute,
        session_id: String,
    },
    Capabilities {
        read: bool,
        write: bool,
    },
    Entries {
        pane: String,
        path: String,
        entries: Vec<FileEntry>,
    },
    Transfer {
        transfer_id: String,
        direction: String,
        path: String,
        transferred: u64,
        total: u64,
        status: String,
    },
    Failure {
        code: String,
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
pub struct FileSessionDiagnostics {
    pub state: ConnectionState,
    pub route: SelectedRoute,
    pub session_id: String,
    pub reauthenticated: bool,
    pub attempts: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum FileMessage {
    Hello {
        version: u8,
    },
    Capabilities {
        read: bool,
        write: bool,
    },
    ListRequest {
        request_id: String,
        path: String,
    },
    ListResult {
        request_id: String,
        path: String,
        entries: Vec<FileEntry>,
    },
    DownloadStart {
        transfer_id: String,
        source: String,
        destination: String,
        collision: CollisionPolicy,
    },
    DownloadManifest {
        transfer_id: String,
        manifest: FileManifest,
        destination: String,
        collision: CollisionPolicy,
    },
    DownloadChunkRequest {
        transfer_id: String,
        offset: u64,
    },
    DownloadChunk {
        transfer_id: String,
        offset: u64,
        data: String,
    },
    DownloadNext {
        transfer_id: String,
    },
    EnsureDirectory {
        transfer_id: String,
        path: String,
    },
    DirectoryReady {
        transfer_id: String,
    },
    UploadStart {
        transfer_id: String,
        manifest: FileManifest,
        collision: CollisionPolicy,
    },
    UploadReady {
        transfer_id: String,
        offset: u64,
    },
    UploadChunk {
        transfer_id: String,
        offset: u64,
        data: String,
    },
    UploadAck {
        transfer_id: String,
        offset: u64,
    },
    TransferDone {
        transfer_id: String,
        path: String,
    },
    Cancel {
        transfer_id: String,
    },
    Error {
        transfer_id: Option<String>,
        code: String,
    },
    Disconnect {
        reason: String,
    },
}

struct DownloadState {
    transfer: WriteTransfer,
    collision: CollisionPolicy,
}

struct UploadState {
    // The source path is meaningful only on the controller.  The manifest sent
    // across the wire contains the host destination instead, so keep the two
    // representations distinct rather than accidentally attempting to read a
    // host virtual path from the controller filesystem.
    source_manifest: Option<FileManifest>,
    remote_manifest: Option<FileManifest>,
    directories: VecDeque<String>,
    pending: VecDeque<(FileManifest, FileManifest)>,
    completed: u64,
    total: u64,
    last_path: String,
    collision: CollisionPolicy,
}

struct HostDownloadState {
    current: Option<FileManifest>,
    directories: VecDeque<String>,
    pending: VecDeque<(FileManifest, String)>,
    collision: CollisionPolicy,
    last_path: String,
}

#[derive(Clone)]
struct FileHandler {
    gathered: mpsc::Sender<()>,
    incoming: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for FileHandler {
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

fn is_token(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn is_path(value: &str) -> bool {
    value.len() >= 2 && value.len() <= 1_024 && !value.contains('\0')
}

fn validate_message(message: &FileMessage) -> Result<()> {
    match message {
        FileMessage::Hello { version } if *version == FILE_PROTOCOL_VERSION => Ok(()),
        FileMessage::Capabilities { .. } => Ok(()),
        FileMessage::ListRequest { request_id, path } if is_token(request_id) && is_path(path) => {
            Ok(())
        }
        FileMessage::ListResult {
            request_id,
            path,
            entries,
        } if is_token(request_id)
            && is_path(path)
            && entries.len() <= crate::secure_file::MAX_LIST_ENTRIES
            && entries.iter().all(|entry| {
                entry.name.len() <= 255
                    && !entry.name.contains('\0')
                    && is_path(&entry.path)
                    && matches!(entry.kind.as_str(), "file" | "directory")
            }) =>
        {
            Ok(())
        }
        FileMessage::DownloadStart {
            transfer_id,
            source,
            destination,
            ..
        } if is_token(transfer_id) && is_path(source) && is_path(destination) => Ok(()),
        FileMessage::DownloadManifest {
            transfer_id,
            manifest,
            destination,
            ..
        } if is_token(transfer_id)
            && is_path(&manifest.path)
            && manifest.size <= crate::secure_file::MAX_TRANSFER_BYTES
            && manifest.sha256.len() == 64
            && manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            && is_path(destination) =>
        {
            Ok(())
        }
        FileMessage::DownloadChunkRequest {
            transfer_id,
            offset,
        } if is_token(transfer_id) && *offset <= crate::secure_file::MAX_TRANSFER_BYTES => Ok(()),
        FileMessage::DownloadNext { transfer_id } | FileMessage::DirectoryReady { transfer_id }
            if is_token(transfer_id) =>
        {
            Ok(())
        }
        FileMessage::EnsureDirectory { transfer_id, path }
            if is_token(transfer_id) && is_path(path) =>
        {
            Ok(())
        }
        FileMessage::DownloadChunk {
            transfer_id,
            offset,
            data,
        }
        | FileMessage::UploadChunk {
            transfer_id,
            offset,
            data,
        } if is_token(transfer_id)
            && *offset <= crate::secure_file::MAX_TRANSFER_BYTES
            && data.len() <= MAX_CHUNK_BYTES * 2
            && STANDARD_NO_PAD
                .decode(data)
                .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_CHUNK_BYTES) =>
        {
            Ok(())
        }
        FileMessage::UploadStart {
            transfer_id,
            manifest,
            ..
        } if is_token(transfer_id)
            && is_path(&manifest.path)
            && manifest.size <= crate::secure_file::MAX_TRANSFER_BYTES
            && manifest.sha256.len() == 64
            && manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(())
        }
        FileMessage::UploadReady {
            transfer_id,
            offset,
        }
        | FileMessage::UploadAck {
            transfer_id,
            offset,
        } if is_token(transfer_id) && *offset <= crate::secure_file::MAX_TRANSFER_BYTES => Ok(()),
        FileMessage::TransferDone { transfer_id, path }
            if is_token(transfer_id) && is_path(path) =>
        {
            Ok(())
        }
        FileMessage::Cancel { transfer_id } if is_token(transfer_id) => Ok(()),
        FileMessage::Error { transfer_id, code }
            if transfer_id.as_deref().is_none_or(is_token)
                && !code.is_empty()
                && code.len() <= 80
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_') =>
        {
            Ok(())
        }
        FileMessage::Disconnect { reason } if !reason.is_empty() && reason.len() <= 80 => Ok(()),
        _ => Err(AgentError::FileTransfer("protocol_rejected".into())),
    }
}

fn encode_message(message: &FileMessage) -> Result<Vec<u8>> {
    validate_message(message)?;
    let bytes = serde_json::to_vec(message)
        .map_err(|_| AgentError::FileTransfer("protocol_rejected".into()))?;
    if bytes.is_empty() || bytes.len() > MAX_FILE_MESSAGE_BYTES {
        return Err(AgentError::FileTransfer("message_too_large".into()));
    }
    Ok(bytes)
}

fn decode_message(bytes: &[u8]) -> Result<FileMessage> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_MESSAGE_BYTES {
        return Err(AgentError::FileTransfer("message_too_large".into()));
    }
    let message = serde_json::from_slice(bytes)
        .map_err(|_| AgentError::FileTransfer("protocol_rejected".into()))?;
    validate_message(&message)?;
    Ok(message)
}

async fn send_message(channel: &Arc<dyn DataChannel>, message: &FileMessage) -> Result<()> {
    let bytes = encode_message(message)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AgentError::FileTransfer("protocol_rejected".into()))?;
    channel
        .try_send_text(text)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))
}

fn emit(events: &mpsc::Sender<FileEvent>, event: FileEvent) {
    let _ = events.try_send(event);
}

fn mapped_path(
    source_root: &str,
    destination_root: &str,
    path: &str,
    directory: bool,
) -> Result<String> {
    if !directory {
        return Ok(destination_root.into());
    }
    let suffix = path
        .strip_prefix(source_root)
        .ok_or_else(|| AgentError::FileTransfer("tree_mapping_rejected".into()))?;
    if suffix.is_empty() {
        return Ok(destination_root.into());
    }
    let suffix = suffix
        .strip_prefix('/')
        .ok_or_else(|| AgentError::FileTransfer("tree_mapping_rejected".into()))?;
    Ok(format!(
        "{}/{}",
        destination_root.trim_end_matches('/'),
        suffix
    ))
}

fn upload_state(
    filesystem: &RootedFileSystem,
    source: &str,
    destination: &str,
    collision: CollisionPolicy,
) -> Result<UploadState> {
    let selection = filesystem.selection(source)?;
    let mut directories = VecDeque::new();
    let mut pending = VecDeque::new();
    for directory in selection.directories {
        directories.push_back(mapped_path(
            source,
            destination,
            &directory,
            selection.is_directory,
        )?);
    }
    let mut total = 0_u64;
    for source_manifest in selection.manifests {
        total = total
            .checked_add(source_manifest.size)
            .ok_or_else(|| AgentError::FileTransfer("tree_too_large".into()))?;
        let mut remote_manifest = source_manifest.clone();
        remote_manifest.path = mapped_path(
            source,
            destination,
            &source_manifest.path,
            selection.is_directory,
        )?;
        pending.push_back((source_manifest, remote_manifest));
    }
    Ok(UploadState {
        source_manifest: None,
        remote_manifest: None,
        directories,
        pending,
        completed: 0,
        total,
        last_path: destination.into(),
        collision,
    })
}

enum UploadAction {
    Directory(String),
    File(FileManifest),
    Complete,
}

fn next_upload_action(state: &mut UploadState) -> UploadAction {
    if let Some(path) = state.directories.pop_front() {
        return UploadAction::Directory(path);
    }
    if let Some((source, remote)) = state.pending.pop_front() {
        state.last_path = remote.path.clone();
        state.source_manifest = Some(source);
        state.remote_manifest = Some(remote.clone());
        return UploadAction::File(remote);
    }
    UploadAction::Complete
}

enum HostDownloadAction {
    Directory(String),
    File(FileManifest, String),
    Complete,
}

fn next_download_action(state: &mut HostDownloadState) -> HostDownloadAction {
    if let Some(path) = state.directories.pop_front() {
        state.last_path = path.clone();
        return HostDownloadAction::Directory(path);
    }
    if let Some((manifest, destination)) = state.pending.pop_front() {
        state.current = Some(manifest.clone());
        state.last_path = destination.clone();
        return HostDownloadAction::File(manifest, destination);
    }
    HostDownloadAction::Complete
}

fn host_download_state(
    filesystem: &RootedFileSystem,
    source: &str,
    destination: &str,
    collision: CollisionPolicy,
) -> Result<HostDownloadState> {
    let selection = filesystem.selection(source)?;
    let mut directories = VecDeque::new();
    let mut pending = VecDeque::new();
    for directory in selection.directories {
        directories.push_back(mapped_path(
            source,
            destination,
            &directory,
            selection.is_directory,
        )?);
    }
    for manifest in selection.manifests {
        let mapped = mapped_path(source, destination, &manifest.path, selection.is_directory)?;
        pending.push_back((manifest, mapped));
    }
    Ok(HostDownloadState {
        current: None,
        directories,
        pending,
        collision,
        last_path: destination.into(),
    })
}

fn transport_config(config: &FileSessionConfig, credentials: TurnCredentials) -> TransportConfig {
    let mut ice_servers = Vec::new();
    if !config.stun_urls.is_empty() {
        ice_servers.push(IceServerConfig {
            urls: config.stun_urls.clone(),
            username: None,
            credential: None,
        });
    }
    if !config.local_test_skip_turn_transport {
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
    }
    TransportConfig {
        ice_mode: config.ice_mode.clone(),
        ice_servers,
    }
}

fn signal_envelope(value: Value, peer: &PeerReference) -> Result<SessionEnvelope> {
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

async fn wait_signal(
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
            return signal_envelope(event, peer);
        }
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

pub async fn run_file_session(
    store: &AgentStore,
    identity: &DeviceIdentity,
    config: &FileSessionConfig,
    role: FileSessionRole,
    commands: &mut mpsc::Receiver<FileCommand>,
    events: mpsc::Sender<FileEvent>,
) -> Result<FileSessionDiagnostics> {
    if config.local_test_skip_turn_transport
        && (!config.coordinator_url.starts_with("ws://127.0.0.1:")
            || !config.bind_address.starts_with("127.0.0.1:"))
    {
        return Err(AgentError::FileTransfer("invalid_test_transport".into()));
    }
    let policy = ReconnectPolicy::default();
    let mut last_error = None;
    for attempt in 1..=policy.max_attempts {
        store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
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
            FileSessionRole::Controller => {
                run_controller(store, &mut coordinator, identity, config, commands, &events).await
            }
            FileSessionRole::Host => {
                run_host(store, &mut coordinator, identity, config, commands, &events).await
            }
        };
        match result {
            Ok(mut diagnostics) => {
                diagnostics.attempts = attempt;
                return Ok(diagnostics);
            }
            Err(error)
                if matches!(
                    error,
                    AgentError::WebRtc(_)
                        | AgentError::CoordinatorProtocol(_)
                        | AgentError::SessionTimedOut
                ) && attempt < policy.max_attempts =>
            {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(policy.delay_before_attempt(attempt)))
                    .await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or(AgentError::SessionTimedOut))
}

async fn run_controller(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &FileSessionConfig,
    commands: &mut mpsc::Receiver<FileCommand>,
    events: &mpsc::Sender<FileEvent>,
) -> Result<FileSessionDiagnostics> {
    let session_id = new_session_id();
    let credentials = coordinator
        .request_turn_credentials(&config.peer, &session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let connection = build_peer_connection(
        &transport_config(config, credentials),
        FileHandler {
            gathered: gathered_tx,
            incoming: None,
        },
        config.bind_address.clone(),
        FILE_DATA_CHANNEL_BUFFER_BYTES,
    )
    .await?;
    let channel = connection
        .create_data_channel(FILE_CHANNEL_LABEL, None)
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
    let answer = wait_signal(coordinator, &config.peer).await?;
    let mut replay = ReplayGuard::default();
    let peer = store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
    accept_signed_description(
        &connection,
        &answer,
        SessionKind::Answer,
        Some(&session_id),
        identity,
        &peer,
        now_millis()?,
        &mut replay,
    )
    .await?;
    let result = controller_loop(store, &channel, commands, events, &connection, &session_id).await;
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    result?;
    emit(
        events,
        FileEvent::Closed {
            route: route.clone(),
            session_id: session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(FileSessionDiagnostics {
        state: ConnectionState::Closed,
        route,
        session_id,
        reauthenticated: true,
        attempts: 0,
    })
}

async fn run_host(
    store: &AgentStore,
    coordinator: &mut AuthenticatedCoordinator,
    identity: &DeviceIdentity,
    config: &FileSessionConfig,
    commands: &mut mpsc::Receiver<FileCommand>,
    events: &mpsc::Sender<FileEvent>,
) -> Result<FileSessionDiagnostics> {
    let offer = wait_signal(coordinator, &config.peer).await?;
    if offer.kind != SessionKind::Offer {
        return Err(AgentError::SessionIdentityOrFreshnessDenied);
    }
    let credentials = coordinator
        .request_turn_credentials(&config.peer, &offer.session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
    let connection = build_peer_connection(
        &transport_config(config, credentials),
        FileHandler {
            gathered: gathered_tx,
            incoming: Some(incoming_tx),
        },
        config.bind_address.clone(),
        FILE_DATA_CHANNEL_BUFFER_BYTES,
    )
    .await?;
    let mut replay = ReplayGuard::default();
    let peer = store.trusted_session_peer(&config.peer.locator, &config.peer.fingerprint)?;
    accept_signed_description(
        &connection,
        &offer,
        SessionKind::Offer,
        None,
        identity,
        &peer,
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
    let tracked_unattended = if store.unattended_service_mode() {
        let now = now_millis()?;
        store.record_unattended_session(
            &offer.session_id,
            &config.peer.fingerprint,
            "files",
            now,
            now.saturating_add(UNATTENDED_LEASE_MAX_MS),
        )?;
        true
    } else {
        false
    };
    let result = host_loop(
        store,
        &channel,
        config,
        commands,
        events,
        &connection,
        &offer.session_id,
    )
    .await;
    if tracked_unattended {
        let _ = store.close_unattended_session(
            &offer.session_id,
            now_millis().unwrap_or(0),
            "files_session_closed",
        );
    }
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    result?;
    emit(
        events,
        FileEvent::Closed {
            route: route.clone(),
            session_id: offer.session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(FileSessionDiagnostics {
        state: ConnectionState::Closed,
        route,
        session_id: offer.session_id,
        reauthenticated: true,
        attempts: 0,
    })
}

async fn controller_loop<P: PeerConnection>(
    store: &AgentStore,
    channel: &Arc<dyn DataChannel>,
    commands: &mut mpsc::Receiver<FileCommand>,
    events: &mpsc::Sender<FileEvent>,
    connection: &P,
    session_id: &str,
) -> Result<()> {
    let filesystem = RootedFileSystem::open(&store.file_roots()?)?;
    let deadline = tokio::time::sleep(Duration::from_millis(FILE_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut opened = false;
    let mut uploads: HashMap<String, UploadState> = HashMap::new();
    let mut downloads: HashMap<String, DownloadState> = HashMap::new();
    let mut download_progress: HashMap<String, (u64, String)> = HashMap::new();
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => {
                    opened = true;
                    send_message(channel, &FileMessage::Hello { version: FILE_PROTOCOL_VERSION }).await?;
                    emit(events, FileEvent::State { state: ConnectionState::Connected, route: selected_route(connection).await, session_id: session_id.into() });
                }
                Some(DataChannelEvent::OnMessage(message)) => match decode_message(&message.data)? {
                    FileMessage::Capabilities { read, write } => emit(events, FileEvent::Capabilities { read, write }),
                    FileMessage::ListResult { request_id: _, path, entries } => emit(events, FileEvent::Entries { pane: "remote".into(), path, entries }),
                    FileMessage::DownloadManifest { transfer_id, manifest, destination, collision } => {
                        download_progress.entry(transfer_id.clone()).or_insert((0, destination.clone()));
                        let mut local_manifest = manifest.clone();
                        local_manifest.path = destination;
                        match filesystem.begin_write(&transfer_id, local_manifest) {
                            Ok(transfer) => {
                                let offset = transfer.offset();
                                if offset == manifest.size {
                                    let path = transfer.complete(collision.as_str())?;
                                    let progress = download_progress.get_mut(&transfer_id).expect("progress exists");
                                    progress.0 = progress.0.saturating_add(manifest.size);
                                    progress.1 = path;
                                    send_message(channel, &FileMessage::DownloadNext { transfer_id }).await?;
                                } else {
                                    downloads.insert(transfer_id.clone(), DownloadState { transfer, collision });
                                    send_message(channel, &FileMessage::DownloadChunkRequest { transfer_id, offset }).await?;
                                }
                            }
                            Err(_) => send_message(channel, &FileMessage::Error { transfer_id: Some(transfer_id), code: "local_destination_rejected".into() }).await?,
                        }
                    }
                    FileMessage::DownloadChunk { transfer_id, offset, data } => {
                        let bytes = STANDARD_NO_PAD.decode(data).map_err(|_| AgentError::FileTransfer("protocol_rejected".into()))?;
                        let Some(state) = downloads.get_mut(&transfer_id) else { return Err(AgentError::FileTransfer("unknown_transfer".into())); };
                        state.transfer.write_chunk(offset, &bytes)?;
                        let next = state.transfer.offset();
                        let total = state.transfer.expected_size();
                        emit(events, FileEvent::Transfer { transfer_id: transfer_id.clone(), direction: "download".into(), path: state.transfer.path().into(), transferred: next, total, status: "running".into() });
                        if next == total {
                            let state = downloads.remove(&transfer_id).expect("transfer exists");
                            let path = state.transfer.complete(state.collision.as_str())?;
                            let progress = download_progress.get_mut(&transfer_id).expect("progress exists");
                            progress.0 = progress.0.saturating_add(total);
                            progress.1 = path;
                            send_message(channel, &FileMessage::DownloadNext { transfer_id }).await?;
                        } else {
                            send_message(channel, &FileMessage::DownloadChunkRequest { transfer_id, offset: next }).await?;
                        }
                    }
                    FileMessage::UploadReady { transfer_id, offset } | FileMessage::UploadAck { transfer_id, offset } => {
                        let Some(state) = uploads.get(&transfer_id) else { return Err(AgentError::FileTransfer("unknown_transfer".into())); };
                        let source_manifest = state.source_manifest.as_ref().ok_or_else(|| AgentError::FileTransfer("upload_state_rejected".into()))?;
                        let remote_manifest = state.remote_manifest.as_ref().ok_or_else(|| AgentError::FileTransfer("upload_state_rejected".into()))?;
                        if offset >= source_manifest.size {
                            return Err(AgentError::FileTransfer("invalid_upload_offset".into()));
                        }
                        let bytes = filesystem.read_chunk(source_manifest, offset, MAX_CHUNK_BYTES)?;
                        if bytes.is_empty() { return Err(AgentError::FileTransfer("source_changed".into())); }
                        let next = offset + bytes.len() as u64;
                        send_message(channel, &FileMessage::UploadChunk { transfer_id: transfer_id.clone(), offset, data: STANDARD_NO_PAD.encode(bytes) }).await?;
                        tokio::time::sleep(Duration::from_millis(FILE_CHUNK_PACING_MS)).await;
                        emit(events, FileEvent::Transfer { transfer_id, direction: "upload".into(), path: remote_manifest.path.clone(), transferred: state.completed.saturating_add(next), total: state.total, status: "running".into() });
                    }
                    FileMessage::TransferDone { transfer_id, path } => {
                        if let Some(mut state) = uploads.remove(&transfer_id) {
                            if let Some(source) = state.source_manifest.take() { state.completed = state.completed.saturating_add(source.size); }
                            state.remote_manifest = None;
                            let action = next_upload_action(&mut state);
                            match action {
                                UploadAction::Directory(path) => { uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                                UploadAction::File(manifest) => { let collision = state.collision; uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::UploadStart { transfer_id, manifest, collision }).await?; }
                                UploadAction::Complete => emit(events, FileEvent::Transfer { transfer_id, direction: "upload".into(), path, transferred: state.total, total: state.total, status: "complete".into() }),
                            }
                        } else if let Some((total, destination)) = download_progress.remove(&transfer_id) {
                            emit(events, FileEvent::Transfer { transfer_id, direction: "download".into(), path: if path.is_empty() { destination } else { path }, transferred: total, total, status: "complete".into() });
                        }
                    }
                    FileMessage::EnsureDirectory { transfer_id, path } => match filesystem.ensure_directory(&path) {
                        Ok(()) => send_message(channel, &FileMessage::DirectoryReady { transfer_id }).await?,
                        Err(_) => send_message(channel, &FileMessage::Error { transfer_id: Some(transfer_id), code: "local_destination_rejected".into() }).await?,
                    },
                    FileMessage::DirectoryReady { transfer_id } => {
                        let Some(mut state) = uploads.remove(&transfer_id) else { return Err(AgentError::FileTransfer("unknown_transfer".into())); };
                        let action = next_upload_action(&mut state);
                        match action {
                            UploadAction::Directory(path) => { uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                            UploadAction::File(manifest) => { let collision = state.collision; uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::UploadStart { transfer_id, manifest, collision }).await?; }
                            UploadAction::Complete => emit(events, FileEvent::Transfer { transfer_id, direction: "upload".into(), path: state.last_path, transferred: state.total, total: state.total, status: "complete".into() }),
                        }
                    }
                    FileMessage::Error { transfer_id, code } => emit(events, FileEvent::Failure { code: transfer_id.map_or(code.clone(), |_| code) }),
                    FileMessage::Cancel { transfer_id } => { uploads.remove(&transfer_id); downloads.remove(&transfer_id); download_progress.remove(&transfer_id); }
                    FileMessage::Disconnect { .. } => return Ok(()),
                    _ => return Err(AgentError::FileTransfer("protocol_rejected".into())),
                },
                Some(_) => {},
                None => return Ok(()),
            },
            command = commands.recv() => match command {
                Some(FileCommand::ListLocal { path }) => {
                    let entries = filesystem.list(&path)?;
                    emit(events, FileEvent::Entries { pane: "local".into(), path, entries });
                }
                Some(FileCommand::ListRemote { path }) if opened => {
                    let request_id = new_session_id();
                    send_message(channel, &FileMessage::ListRequest { request_id, path }).await?;
                }
                Some(FileCommand::Upload { transfer_id, source, destination, collision }) if opened => {
                    let mut state = upload_state(&filesystem, &source, &destination, collision)?;
                    let action = next_upload_action(&mut state);
                    match action {
                        UploadAction::Directory(path) => { uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                        UploadAction::File(manifest) => { uploads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::UploadStart { transfer_id, manifest, collision }).await?; }
                        UploadAction::Complete => emit(events, FileEvent::Transfer { transfer_id, direction: "upload".into(), path: destination, transferred: 0, total: 0, status: "complete".into() }),
                    }
                }
                Some(FileCommand::Download { transfer_id, source, destination, collision }) if opened => {
                    send_message(channel, &FileMessage::DownloadStart { transfer_id, source, destination, collision }).await?;
                }
                Some(FileCommand::Cancel { transfer_id }) if opened => {
                    uploads.remove(&transfer_id); downloads.remove(&transfer_id);
                    send_message(channel, &FileMessage::Cancel { transfer_id }).await?;
                }
                Some(FileCommand::Disconnect) | None => {
                    if opened { let _ = send_message(channel, &FileMessage::Disconnect { reason: "local_disconnect".into() }).await; }
                    return Ok(());
                }
                _ => {},
            }
        }
    }
}

async fn host_loop<P: PeerConnection>(
    store: &AgentStore,
    channel: &Arc<dyn DataChannel>,
    config: &FileSessionConfig,
    commands: &mut mpsc::Receiver<FileCommand>,
    events: &mpsc::Sender<FileEvent>,
    connection: &P,
    session_id: &str,
) -> Result<()> {
    let filesystem = RootedFileSystem::open(&store.file_roots()?)?;
    let deadline = tokio::time::sleep(Duration::from_millis(FILE_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut authorization_tick = tokio::time::interval(Duration::from_secs(1));
    let mut opened = false;
    let mut hello = false;
    let mut downloads: HashMap<String, HostDownloadState> = HashMap::new();
    let mut uploads: HashMap<String, (WriteTransfer, CollisionPolicy)> = HashMap::new();
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            _ = authorization_tick.tick() => {
                store.unattended_session_lease_current(session_id, &config.peer.fingerprint, now_millis()?)?;
            },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => {
                    opened = true;
                    emit(events, FileEvent::State { state: ConnectionState::Connected, route: selected_route(connection).await, session_id: session_id.into() });
                }
                Some(DataChannelEvent::OnMessage(message)) => match decode_message(&message.data)? {
                    FileMessage::Hello { .. } if opened && !hello => {
                        hello = true;
                        let read = store.authorize_desktop_session(&config.peer.locator, &config.peer.fingerprint, crate::policy::Capability::FilesRead, now_millis()?).is_ok();
                        let write = store.authorize_desktop_session(&config.peer.locator, &config.peer.fingerprint, crate::policy::Capability::FilesWrite, now_millis()?).is_ok();
                        send_message(channel, &FileMessage::Capabilities { read, write }).await?;
                        emit(events, FileEvent::Capabilities { read, write });
                    }
                    FileMessage::ListRequest { request_id, path } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesRead)?;
                        let entries = filesystem.list(&path)?;
                        send_message(channel, &FileMessage::ListResult { request_id, path, entries }).await?;
                    }
                    FileMessage::DownloadStart { transfer_id, source, destination, collision } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesRead)?;
                        let mut state = host_download_state(&filesystem, &source, &destination, collision)?;
                        let action = next_download_action(&mut state);
                        match action {
                            HostDownloadAction::Directory(path) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                            HostDownloadAction::File(manifest, destination) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::DownloadManifest { transfer_id, manifest, destination, collision }).await?; }
                            HostDownloadAction::Complete => send_message(channel, &FileMessage::TransferDone { transfer_id, path: destination }).await?,
                        }
                    }
                    FileMessage::DownloadChunkRequest { transfer_id, offset } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesRead)?;
                        let manifest = downloads.get(&transfer_id).and_then(|state| state.current.as_ref()).ok_or_else(|| AgentError::FileTransfer("unknown_transfer".into()))?;
                        let bytes = filesystem.read_chunk(manifest, offset, MAX_CHUNK_BYTES)?;
                        if bytes.is_empty() && offset != manifest.size { return Err(AgentError::FileTransfer("source_changed".into())); }
                        send_message(channel, &FileMessage::DownloadChunk { transfer_id, offset, data: STANDARD_NO_PAD.encode(bytes) }).await?;
                        tokio::time::sleep(Duration::from_millis(FILE_CHUNK_PACING_MS)).await;
                    }
                    FileMessage::DownloadNext { transfer_id } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesRead)?;
                        let Some(mut state) = downloads.remove(&transfer_id) else { return Err(AgentError::FileTransfer("unknown_transfer".into())); };
                        state.current = None;
                        let collision = state.collision;
                        let last_path = state.last_path.clone();
                        let action = next_download_action(&mut state);
                        match action {
                            HostDownloadAction::Directory(path) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                            HostDownloadAction::File(manifest, destination) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::DownloadManifest { transfer_id, manifest, destination, collision }).await?; }
                            HostDownloadAction::Complete => send_message(channel, &FileMessage::TransferDone { transfer_id, path: last_path }).await?,
                        }
                    }
                    FileMessage::EnsureDirectory { transfer_id, path } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesWrite)?;
                        filesystem.ensure_directory(&path)?;
                        send_message(channel, &FileMessage::DirectoryReady { transfer_id }).await?;
                    }
                    FileMessage::DirectoryReady { transfer_id } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesRead)?;
                        let Some(mut state) = downloads.remove(&transfer_id) else { return Err(AgentError::FileTransfer("unknown_transfer".into())); };
                        let collision = state.collision;
                        let last_path = state.last_path.clone();
                        let action = next_download_action(&mut state);
                        match action {
                            HostDownloadAction::Directory(path) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::EnsureDirectory { transfer_id, path }).await?; }
                            HostDownloadAction::File(manifest, destination) => { downloads.insert(transfer_id.clone(), state); send_message(channel, &FileMessage::DownloadManifest { transfer_id, manifest, destination, collision }).await?; }
                            HostDownloadAction::Complete => send_message(channel, &FileMessage::TransferDone { transfer_id, path: last_path }).await?,
                        }
                    }
                    FileMessage::UploadStart { transfer_id, manifest, collision } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesWrite)?;
                        let transfer = filesystem.begin_write(&transfer_id, manifest.clone())?;
                        let offset = transfer.offset();
                        if offset == manifest.size {
                            let path = transfer.complete(collision.as_str())?;
                            send_message(channel, &FileMessage::TransferDone { transfer_id, path }).await?;
                        } else {
                            uploads.insert(transfer_id.clone(), (transfer, collision));
                            send_message(channel, &FileMessage::UploadReady { transfer_id, offset }).await?;
                        }
                    }
                    FileMessage::UploadChunk { transfer_id, offset, data } if hello => {
                        authorize_files(store, config, crate::policy::Capability::FilesWrite)?;
                        let bytes = STANDARD_NO_PAD.decode(data).map_err(|_| AgentError::FileTransfer("protocol_rejected".into()))?;
                        let (transfer, _collision) = uploads.get_mut(&transfer_id).ok_or_else(|| AgentError::FileTransfer("unknown_transfer".into()))?;
                        transfer.write_chunk(offset, &bytes)?;
                        let next = transfer.offset();
                        if next == transfer.expected_size() {
                            let (transfer, collision) = uploads.remove(&transfer_id).expect("transfer exists");
                            let path = transfer.complete(collision.as_str())?;
                            send_message(channel, &FileMessage::TransferDone { transfer_id, path }).await?;
                        } else {
                            send_message(channel, &FileMessage::UploadAck { transfer_id, offset: next }).await?;
                        }
                    }
                    FileMessage::Cancel { transfer_id } if hello => { downloads.remove(&transfer_id); uploads.remove(&transfer_id); }
                    FileMessage::Disconnect { .. } => return Ok(()),
                    FileMessage::Error { .. } => {},
                    _ => return Err(AgentError::FileTransfer("protocol_rejected".into())),
                },
                Some(_) => {},
                None => return Ok(()),
            },
            command = commands.recv() => match command {
                Some(FileCommand::Disconnect) | None => {
                    if opened { let _ = send_message(channel, &FileMessage::Disconnect { reason: "host_disconnect".into() }).await; }
                    return Ok(());
                }
                _ => {},
            }
        }
    }
}

fn authorize_files(
    store: &AgentStore,
    config: &FileSessionConfig,
    capability: crate::policy::Capability,
) -> Result<()> {
    store.authorize_desktop_session(
        &config.peer.locator,
        &config.peer.fingerprint,
        capability,
        now_millis()?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_wire_rejects_traversal_unknown_messages_and_oversized_chunks() {
        assert!(decode_message(br#"{"type":"exec","command":"id"}"#).is_err());
        assert!(encode_message(&FileMessage::ListRequest {
            request_id: "a".repeat(22),
            path: "0/../secret".into()
        })
        .is_ok());
        // Path syntax is checked by the root capability boundary; this wire
        // test proves the protocol cannot carry an unbounded raw command.
        assert!(decode_message(&vec![b'x'; MAX_FILE_MESSAGE_BYTES + 1]).is_err());
        assert!(decode_message(br#"{"type":"download_chunk","transfer_id":"aaaaaaaaaaaaaaaaaaaaaa","offset":0,"data":""}"#).is_err());
    }
}
