//! Native SSH tunnel over the authenticated WebRTC data channel.
//!
//! The controller runs the system OpenSSH client in a local PTY. Its SSH
//! protocol socket is relayed only to the host's locally configured loopback
//! endpoint. The renderer can neither supply another destination nor ask the
//! agent to execute a shell command.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use bytes::BytesMut;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{PeerConnection, PeerConnectionEventHandler, RTCIceGatheringState};

use crate::coordinator::{AuthenticatedCoordinator, ReconnectPolicy, TurnCredentials};
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

const SSH_PROTOCOL_VERSION: u8 = 1;
const SSH_CHANNEL_LABEL: &str = "wii-ssh-v1";
const SSH_CHANNEL_BUFFER_BYTES: usize = 128 * 1024;
const MAX_RAW_SSH_FRAME_BYTES: usize = 16 * 1024;
const MAX_SSH_CONTROL_BYTES: usize = 2 * 1024;
const SSH_SESSION_MAX_MS: u64 = 60 * 60_000;

#[derive(Clone, Debug)]
pub struct SshSessionConfig {
    pub coordinator_url: String,
    pub peer: PeerReference,
    pub ice_mode: IceMode,
    pub stun_urls: Vec<String>,
    pub bind_address: String,
    pub username: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshSessionRole {
    Controller,
    Host,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SshCommand {
    Input { data: String },
    Resize { cols: u16, rows: u16 },
    Disconnect,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshEvent {
    State {
        state: ConnectionState,
        route: SelectedRoute,
        session_id: String,
    },
    Terminal {
        data: String,
    },
    HostKey {
        state: String,
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
pub struct SshSessionDiagnostics {
    pub state: ConnectionState,
    pub route: SelectedRoute,
    pub session_id: String,
    pub reauthenticated: bool,
    pub attempts: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SshControl {
    Hello { version: u8, username: String },
    Ready,
    Error { code: String },
    Disconnect { reason: String },
}

#[derive(Clone)]
struct SshHandler {
    gathered: mpsc::Sender<()>,
    incoming: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for SshHandler {
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

fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn control_bytes(control: &SshControl) -> Result<Vec<u8>> {
    match control {
        SshControl::Hello { version, username }
            if *version == SSH_PROTOCOL_VERSION && valid_username(username) => {}
        SshControl::Ready => {}
        SshControl::Error { code }
            if !code.is_empty()
                && code.len() <= 80
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_') => {}
        SshControl::Disconnect { reason } if !reason.is_empty() && reason.len() <= 80 => {}
        _ => return Err(AgentError::SshUnavailable("protocol_rejected".into())),
    }
    let bytes = serde_json::to_vec(control)
        .map_err(|_| AgentError::SshUnavailable("protocol_rejected".into()))?;
    if bytes.len() > MAX_SSH_CONTROL_BYTES {
        return Err(AgentError::SshUnavailable("control_too_large".into()));
    }
    Ok(bytes)
}

async fn send_control(channel: &Arc<dyn DataChannel>, control: &SshControl) -> Result<()> {
    let bytes = control_bytes(control)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AgentError::SshUnavailable("protocol_rejected".into()))?;
    channel
        .try_send_text(text)
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))
}

async fn send_raw(channel: &Arc<dyn DataChannel>, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RAW_SSH_FRAME_BYTES {
        return Err(AgentError::SshUnavailable("raw_frame_invalid".into()));
    }
    channel
        .try_send(BytesMut::from(bytes))
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))
}

fn decode_control(bytes: &[u8]) -> Result<SshControl> {
    if bytes.is_empty() || bytes.len() > MAX_SSH_CONTROL_BYTES {
        return Err(AgentError::SshUnavailable("protocol_rejected".into()));
    }
    let control: SshControl = serde_json::from_slice(bytes)
        .map_err(|_| AgentError::SshUnavailable("protocol_rejected".into()))?;
    control_bytes(&control)?;
    Ok(control)
}

fn transport_config(config: &SshSessionConfig, credentials: TurnCredentials) -> TransportConfig {
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
        let value = coordinator
            .receive_message(SESSION_CONNECT_TIMEOUT_MS)
            .await?;
        if value
            .as_object()
            .and_then(|object| object.get("type"))
            .and_then(Value::as_str)
            == Some("SIGNAL")
        {
            return signal_envelope(value, peer);
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

fn emit(events: &mpsc::Sender<SshEvent>, event: SshEvent) {
    let _ = events.try_send(event);
}

pub async fn run_ssh_session(
    store: &AgentStore,
    identity: &DeviceIdentity,
    config: &SshSessionConfig,
    role: SshSessionRole,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: mpsc::Sender<SshEvent>,
) -> Result<SshSessionDiagnostics> {
    if !valid_username(&config.username) {
        return Err(AgentError::SshUnavailable("username_invalid".into()));
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
            SshSessionRole::Controller => {
                run_controller(store, &mut coordinator, identity, config, commands, &events).await
            }
            SshSessionRole::Host => {
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
    config: &SshSessionConfig,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: &mpsc::Sender<SshEvent>,
) -> Result<SshSessionDiagnostics> {
    let session_id = new_session_id();
    let credentials = coordinator
        .request_turn_credentials(&config.peer, &session_id)
        .await?;
    let (gathered_tx, mut gathered_rx) = mpsc::channel(1);
    let connection = build_peer_connection(
        &transport_config(config, credentials),
        SshHandler {
            gathered: gathered_tx,
            incoming: None,
        },
        config.bind_address.clone(),
        SSH_CHANNEL_BUFFER_BYTES,
    )
    .await?;
    let channel = connection
        .create_data_channel(SSH_CHANNEL_LABEL, None)
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
    let result = controller_loop(
        store,
        &channel,
        config,
        commands,
        events,
        &connection,
        &session_id,
    )
    .await;
    let route = selected_route(&connection).await;
    connection
        .close()
        .await
        .map_err(|error| AgentError::WebRtc(error.to_string()))?;
    result?;
    emit(
        events,
        SshEvent::Closed {
            route: route.clone(),
            session_id: session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(SshSessionDiagnostics {
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
    config: &SshSessionConfig,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: &mpsc::Sender<SshEvent>,
) -> Result<SshSessionDiagnostics> {
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
        SshHandler {
            gathered: gathered_tx,
            incoming: Some(incoming_tx),
        },
        config.bind_address.clone(),
        SSH_CHANNEL_BUFFER_BYTES,
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
            "ssh",
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
            "ssh_session_closed",
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
        SshEvent::Closed {
            route: route.clone(),
            session_id: offer.session_id.clone(),
            reauthenticated: true,
            attempts: 0,
        },
    );
    Ok(SshSessionDiagnostics {
        state: ConnectionState::Closed,
        route,
        session_id: offer.session_id,
        reauthenticated: true,
        attempts: 0,
    })
}

struct PtyControl {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Box<dyn std::io::Write + Send>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
}
enum PtyNotice {
    Output(Vec<u8>),
    Exited,
}

fn spawn_ssh_pty(
    store: &AgentStore,
    peer: &PeerReference,
    username: &str,
    port: u16,
    cols: u16,
    rows: u16,
    sender: mpsc::Sender<PtyNotice>,
) -> Result<PtyControl> {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|_| AgentError::SshUnavailable("pty_unavailable".into()))?;
    let known_hosts = store.state_dir().join("ssh-known-hosts");
    let mut command = CommandBuilder::new("ssh");
    command.arg("-tt");
    for option in [
        "StrictHostKeyChecking=ask".to_string(),
        format!("UserKnownHostsFile={}", known_hosts.to_string_lossy()),
        #[cfg(windows)]
        "GlobalKnownHostsFile=NUL".to_string(),
        #[cfg(not(windows))]
        "GlobalKnownHostsFile=/dev/null".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "PermitLocalCommand=no".to_string(),
        format!("HostKeyAlias=wii-{}", peer.fingerprint),
    ] {
        command.arg("-o");
        command.arg(option);
    }
    command.arg("-p");
    command.arg(port.to_string());
    command.arg(format!("{username}@127.0.0.1"));
    command.env("TERM", "xterm-256color");
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| AgentError::SshUnavailable("ssh_client_unavailable".into()))?;
    drop(pair.slave);
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| AgentError::SshUnavailable("pty_reader_unavailable".into()))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| AgentError::SshUnavailable("pty_writer_unavailable".into()))?;
    let killer = child.clone_killer();
    std::thread::spawn(move || {
        let mut buffer = [0_u8; MAX_RAW_SSH_FRAME_BYTES];
        loop {
            match std::io::Read::read(&mut reader, &mut buffer) {
                Ok(0) | Err(_) => {
                    let _ = sender.blocking_send(PtyNotice::Exited);
                    break;
                }
                Ok(size) => {
                    if sender
                        .blocking_send(PtyNotice::Output(buffer[..size].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    Ok(PtyControl {
        master: Arc::new(Mutex::new(pair.master)),
        writer: Arc::new(Mutex::new(writer)),
        killer: Arc::new(Mutex::new(killer)),
    })
}

fn terminal_event(events: &mpsc::Sender<SshEvent>, bytes: Vec<u8>) {
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("authenticity of host") && text.contains("continue connecting") {
        emit(
            events,
            SshEvent::HostKey {
                state: "approval_required".into(),
            },
        );
    }
    if text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        emit(
            events,
            SshEvent::HostKey {
                state: "changed_key_rejected".into(),
            },
        );
    }
    emit(
        events,
        SshEvent::Terminal {
            data: STANDARD_NO_PAD.encode(bytes),
        },
    );
}

async fn controller_loop<P: PeerConnection>(
    store: &AgentStore,
    channel: &Arc<dyn DataChannel>,
    config: &SshSessionConfig,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: &mpsc::Sender<SshEvent>,
    connection: &P,
    session_id: &str,
) -> Result<()> {
    let deadline = tokio::time::sleep(Duration::from_millis(SSH_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut authorization_tick = tokio::time::interval(Duration::from_secs(1));
    let mut opened = false;
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            _ = authorization_tick.tick() => {
                store.unattended_session_lease_current(session_id, &config.peer.fingerprint, now_millis()?)?;
            },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => { opened = true; send_control(channel, &SshControl::Hello { version: SSH_PROTOCOL_VERSION, username: config.username.clone() }).await?; emit(events, SshEvent::State { state: ConnectionState::Connecting, route: selected_route(connection).await, session_id: session_id.into() }); }
                Some(DataChannelEvent::OnMessage(message)) if message.is_string => match decode_control(&message.data)? {
                    SshControl::Ready => return run_local_ssh(store, channel, config, commands, events).await,
                    SshControl::Error { code } => return Err(AgentError::SshUnavailable(code)),
                    SshControl::Disconnect { .. } => return Ok(()),
                    _ => return Err(AgentError::SshUnavailable("protocol_rejected".into())),
                },
                Some(DataChannelEvent::OnMessage(_)) => return Err(AgentError::SshUnavailable("raw_before_ready".into())),
                Some(_) => {}, None => return Ok(()),
            },
            command = commands.recv() => match command { Some(SshCommand::Disconnect) | None => { if opened { let _ = send_control(channel, &SshControl::Disconnect { reason: "local_disconnect".into() }).await; } return Ok(()); }, _ => {} }
        }
    }
}

async fn run_local_ssh(
    store: &AgentStore,
    channel: &Arc<dyn DataChannel>,
    config: &SshSessionConfig,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: &mpsc::Sender<SshEvent>,
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| AgentError::SshUnavailable("local_listener_unavailable".into()))?;
    let port = listener
        .local_addr()
        .map_err(|_| AgentError::SshUnavailable("local_listener_unavailable".into()))?
        .port();
    let (notice_sender, mut notices) = mpsc::channel(32);
    let pty = spawn_ssh_pty(
        store,
        &config.peer,
        &config.username,
        port,
        100,
        30,
        notice_sender,
    )?;
    let (mut socket, _) = timeout(
        Duration::from_millis(SESSION_CONNECT_TIMEOUT_MS),
        listener.accept(),
    )
    .await
    .map_err(|_| AgentError::SshUnavailable("ssh_client_connect_timeout".into()))?
    .map_err(|_| AgentError::SshUnavailable("ssh_client_connect_failed".into()))?;
    let mut socket_buffer = [0_u8; MAX_RAW_SSH_FRAME_BYTES];
    let deadline = tokio::time::sleep(Duration::from_millis(SSH_SESSION_MAX_MS));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            read = socket.read(&mut socket_buffer) => match read { Ok(0) => return Ok(()), Ok(size) => send_raw(channel, &socket_buffer[..size]).await?, Err(_) => return Err(AgentError::SshUnavailable("local_ssh_socket_failed".into())) },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnMessage(message)) if !message.is_string => { if message.data.is_empty() || message.data.len() > MAX_RAW_SSH_FRAME_BYTES { return Err(AgentError::SshUnavailable("raw_frame_invalid".into())); } socket.write_all(&message.data).await.map_err(|_| AgentError::SshUnavailable("local_ssh_socket_failed".into()))?; },
                Some(DataChannelEvent::OnMessage(message)) => match decode_control(&message.data)? { SshControl::Disconnect { .. } => return Ok(()), SshControl::Error { code } => return Err(AgentError::SshUnavailable(code)), _ => return Err(AgentError::SshUnavailable("protocol_rejected".into())) },
                Some(_) => {}, None => return Ok(()),
            },
            notice = notices.recv() => match notice { Some(PtyNotice::Output(bytes)) => terminal_event(events, bytes), Some(PtyNotice::Exited) | None => return Ok(()) },
            command = commands.recv() => match command {
                Some(SshCommand::Input { data }) => { let bytes = STANDARD_NO_PAD.decode(data).map_err(|_| AgentError::SshUnavailable("terminal_input_invalid".into()))?; if bytes.is_empty() || bytes.len() > MAX_RAW_SSH_FRAME_BYTES { return Err(AgentError::SshUnavailable("terminal_input_invalid".into())); } pty.writer.lock().map_err(|_| AgentError::SshUnavailable("pty_unavailable".into()))?.write_all(&bytes).map_err(|_| AgentError::SshUnavailable("pty_write_failed".into()))?; },
                Some(SshCommand::Resize { cols, rows }) => { if cols == 0 || rows == 0 || cols > 500 || rows > 300 { return Err(AgentError::SshUnavailable("terminal_resize_invalid".into())); } pty.master.lock().map_err(|_| AgentError::SshUnavailable("pty_unavailable".into()))?.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).map_err(|_| AgentError::SshUnavailable("terminal_resize_failed".into()))?; },
                Some(SshCommand::Disconnect) | None => { let _ = pty.killer.lock().map_err(|_| AgentError::SshUnavailable("pty_unavailable".into()))?.kill(); let _ = send_control(channel, &SshControl::Disconnect { reason: "local_disconnect".into() }).await; return Ok(()); },
            }
        }
    }
}

async fn host_loop<P: PeerConnection>(
    store: &AgentStore,
    channel: &Arc<dyn DataChannel>,
    config: &SshSessionConfig,
    commands: &mut mpsc::Receiver<SshCommand>,
    events: &mpsc::Sender<SshEvent>,
    connection: &P,
    session_id: &str,
) -> Result<()> {
    let deadline = tokio::time::sleep(Duration::from_millis(SSH_SESSION_MAX_MS));
    tokio::pin!(deadline);
    let mut authorization_tick = tokio::time::interval(Duration::from_secs(1));
    let mut opened = false;
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(AgentError::SessionTimedOut),
            _ = authorization_tick.tick() => {
                store.unattended_session_lease_current(session_id, &config.peer.fingerprint, now_millis()?)?;
            },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) if !opened => { opened = true; emit(events, SshEvent::State { state: ConnectionState::Connecting, route: selected_route(connection).await, session_id: session_id.into() }); },
                Some(DataChannelEvent::OnMessage(message)) if message.is_string => match decode_control(&message.data)? {
                    SshControl::Hello { .. } if opened => {
                        store.authorize_desktop_session(&config.peer.locator, &config.peer.fingerprint, crate::policy::Capability::Ssh, now_millis()?)?;
                        let endpoint = store.ssh_endpoint()?;
                        let socket = TcpStream::connect(("127.0.0.1", endpoint.port)).await.map_err(|_| AgentError::SshUnavailable("endpoint_unavailable".into()))?;
                        send_control(channel, &SshControl::Ready).await?;
                        return bridge_endpoint(store, config, channel, socket, commands, session_id).await;
                    }
                    SshControl::Disconnect { .. } => return Ok(()),
                    _ => return Err(AgentError::SshUnavailable("protocol_rejected".into())),
                },
                Some(DataChannelEvent::OnMessage(_)) => return Err(AgentError::SshUnavailable("raw_before_authorization".into())),
                Some(_) => {}, None => return Ok(()),
            },
            command = commands.recv() => if matches!(command, Some(SshCommand::Disconnect) | None) { return Ok(()); },
        }
    }
}

async fn bridge_endpoint(
    store: &AgentStore,
    config: &SshSessionConfig,
    channel: &Arc<dyn DataChannel>,
    mut socket: TcpStream,
    commands: &mut mpsc::Receiver<SshCommand>,
    session_id: &str,
) -> Result<()> {
    let mut buffer = [0_u8; MAX_RAW_SSH_FRAME_BYTES];
    let mut authorization_tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = authorization_tick.tick() => {
                store.unattended_session_lease_current(session_id, &config.peer.fingerprint, now_millis()?)?;
            },
            read = socket.read(&mut buffer) => match read {
                Ok(0) => return Ok(()),
                Ok(size) => { authorize_ssh(store, config)?; send_raw(channel, &buffer[..size]).await? },
                Err(_) => return Err(AgentError::SshUnavailable("endpoint_connection_lost".into())),
            },
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnMessage(message)) if !message.is_string => {
                    if message.data.is_empty() || message.data.len() > MAX_RAW_SSH_FRAME_BYTES { return Err(AgentError::SshUnavailable("raw_frame_invalid".into())); }
                    authorize_ssh(store, config)?;
                    socket.write_all(&message.data).await.map_err(|_| AgentError::SshUnavailable("endpoint_connection_lost".into()))?;
                },
                Some(DataChannelEvent::OnMessage(message)) => match decode_control(&message.data)? { SshControl::Disconnect { .. } => return Ok(()), _ => return Err(AgentError::SshUnavailable("protocol_rejected".into())) },
                Some(_) => {}, None => return Ok(()),
            },
            command = commands.recv() => if matches!(command, Some(SshCommand::Disconnect) | None) { let _ = send_control(channel, &SshControl::Disconnect { reason: "host_disconnect".into() }).await; return Ok(()); },
        }
    }
}

fn authorize_ssh(store: &AgentStore, config: &SshSessionConfig) -> Result<()> {
    store.authorize_desktop_session(
        &config.peer.locator,
        &config.peer.fingerprint,
        crate::policy::Capability::Ssh,
        now_millis()?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_control_rejects_bad_users_and_unbounded_input() {
        assert!(control_bytes(&SshControl::Hello {
            version: 1,
            username: "good-user".into()
        })
        .is_ok());
        assert!(control_bytes(&SshControl::Hello {
            version: 1,
            username: "bad user".into()
        })
        .is_err());
        assert!(decode_control(br#"{"type":"exec","command":"id"}"#).is_err());
        assert!(valid_username("root"));
    }
}
