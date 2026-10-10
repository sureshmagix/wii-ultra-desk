use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::timeout;
use wii_ultra_desk_agent::coordinator::AuthenticatedCoordinator;
use wii_ultra_desk_agent::desktop::{
    capabilities as desktop_capabilities, NativeDesktopHost, QualityMode,
};
use wii_ultra_desk_agent::desktop_session::{
    run_desktop_session, DesktopCommand, DesktopEvent, DesktopSessionConfig, DesktopSessionRole,
};
use wii_ultra_desk_agent::file_session::{
    run_file_session, FileCommand, FileEvent, FileSessionConfig, FileSessionRole,
};
use wii_ultra_desk_agent::lifecycle::{
    local_control_client, request_remote_revocation, run_daemon, socket_path, LocalControlRequest,
};
use wii_ultra_desk_agent::pairing::{controller_pair, host_pair};
use wii_ultra_desk_agent::policy::{Capability, Grant};
use wii_ultra_desk_agent::secure_file::FileRootsConfig;
use wii_ultra_desk_agent::session::{
    run_status_session, SessionDiagnostics, StatusSessionConfig, StatusSessionRole,
};
use wii_ultra_desk_agent::ssh_session::{
    run_ssh_session, SshCommand, SshEvent, SshSessionConfig, SshSessionRole,
};
use wii_ultra_desk_agent::store::{public_identity, AgentStore, ApprovedSshEndpoint};
use wii_ultra_desk_agent::transport::{ConnectionState, IceMode, PeerReference, SelectedRoute};
use wii_ultra_desk_agent::AgentError;

fn state_dir(arguments: &[String]) -> PathBuf {
    if let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--state-dir")
    {
        if let Some(path) = arguments.get(index + 1) {
            return PathBuf::from(path);
        }
    }
    if let Some(path) = std::env::var_os("WII_AGENT_STATE_DIR") {
        return PathBuf::from(path);
    }
    std::env::current_dir()
        .expect("current directory")
        .join(".wii-ultra-desk-agent")
}

fn coordinator_url(arguments: &[String]) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == "--coordinator")
        .and_then(|index| arguments.get(index + 1).cloned())
        .or_else(|| std::env::var("WII_COORDINATOR_URL").ok())
}

fn option(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1).cloned())
}

fn options(arguments: &[String], name: &str) -> Vec<String> {
    arguments
        .windows(2)
        .filter(|window| window[0] == name)
        .map(|window| window[1].clone())
        .collect()
}

fn now_millis() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
}

fn required_option(arguments: &[String], name: &str) -> Result<String, String> {
    option(arguments, name).ok_or_else(|| format!("{name} is required"))
}

fn unattended_capability(value: &str) -> Option<Capability> {
    match value {
        "desktop.view" => Some(Capability::DesktopView),
        "desktop.control" => Some(Capability::DesktopControl),
        "ssh" => Some(Capability::Ssh),
        "files.read" => Some(Capability::FilesRead),
        "files.write" => Some(Capability::FilesWrite),
        _ => None,
    }
}

/// OS permissions are checked only when their matching scope is being
/// enabled. SSH/files can run headlessly; desktop capture/input cannot be
/// silently enabled without the interactive OS consent already in place.
fn verify_unattended_permissions(capabilities: &[Capability]) -> Result<(), AgentError> {
    if capabilities.contains(&Capability::DesktopView) {
        let host = NativeDesktopHost::open(None)?;
        let _ = host.capture(QualityMode::LowBandwidth.profile())?;
    }
    if capabilities.contains(&Capability::DesktopControl) {
        let mut host = NativeDesktopHost::open(None)?;
        host.verify_input_permission()?;
    }
    Ok(())
}

fn local_control_request(arguments: &[String]) -> Result<LocalControlRequest, String> {
    let action = required_option(arguments, "--action")?;
    match action.as_str() {
        "status" => Ok(LocalControlRequest::Status { version: 1 }),
        "trusted-devices" => Ok(LocalControlRequest::TrustedDevices { version: 1 }),
        "security-events" => Ok(LocalControlRequest::SecurityEvents {
            version: 1,
            limit: option(arguments, "--limit")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(50),
        }),
        "disconnect" => Ok(LocalControlRequest::Disconnect {
            version: 1,
            confirmation: "disconnect_unattended".into(),
        }),
        "disable" => Ok(LocalControlRequest::Disable {
            version: 1,
            confirmation: "disable_unattended".into(),
        }),
        _ => Err(
            "--action must be status, trusted-devices, security-events, disconnect, or disable"
                .into(),
        ),
    }
}

fn status_config(arguments: &[String]) -> Result<StatusSessionConfig, String> {
    let coordinator_url = required_option(arguments, "--coordinator")?;
    let locator = required_option(arguments, "--peer-locator")?;
    let fingerprint = required_option(arguments, "--peer-fingerprint")?;
    let ice_mode = match option(arguments, "--ice-mode")
        .as_deref()
        .unwrap_or("automatic")
    {
        "automatic" => IceMode::Automatic,
        "relay-only" => IceMode::RelayOnlyDiagnostic,
        _ => return Err("--ice-mode must be automatic or relay-only".into()),
    };
    Ok(StatusSessionConfig {
        coordinator_url,
        peer: PeerReference {
            locator,
            fingerprint,
        },
        ice_mode,
        stun_urls: options(arguments, "--stun"),
        bind_address: option(arguments, "--bind").unwrap_or_else(|| "0.0.0.0:0".into()),
        local_test_skip_turn_transport: arguments
            .iter()
            .any(|argument| argument == "--local-test-skip-turn-transport"),
    })
}

fn desktop_config(arguments: &[String]) -> Result<DesktopSessionConfig, String> {
    let coordinator_url = required_option(arguments, "--coordinator")?;
    let locator = required_option(arguments, "--peer-locator")?;
    let fingerprint = required_option(arguments, "--peer-fingerprint")?;
    let ice_mode = match option(arguments, "--ice-mode")
        .as_deref()
        .unwrap_or("automatic")
    {
        "automatic" => IceMode::Automatic,
        "relay-only" => IceMode::RelayOnlyDiagnostic,
        _ => return Err("--ice-mode must be automatic or relay-only".into()),
    };
    let quality = match option(arguments, "--quality").as_deref().unwrap_or("auto") {
        "auto" => QualityMode::Auto,
        "clear-text" => QualityMode::ClearText,
        "smooth-motion" => QualityMode::SmoothMotion,
        "low-bandwidth" => QualityMode::LowBandwidth,
        _ => {
            return Err(
                "--quality must be auto, clear-text, smooth-motion, or low-bandwidth".into(),
            )
        }
    };
    let monitor_id = option(arguments, "--monitor")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "--monitor must be a numeric native monitor ID".to_string())
        })
        .transpose()?;
    Ok(DesktopSessionConfig {
        coordinator_url,
        peer: PeerReference {
            locator,
            fingerprint,
        },
        ice_mode,
        stun_urls: options(arguments, "--stun"),
        bind_address: option(arguments, "--bind").unwrap_or_else(|| "0.0.0.0:0".into()),
        monitor_id,
        quality,
        control_requested: arguments
            .iter()
            .any(|argument| argument == "--request-control"),
    })
}

fn file_config(arguments: &[String]) -> Result<FileSessionConfig, String> {
    let coordinator_url = required_option(arguments, "--coordinator")?;
    let locator = required_option(arguments, "--peer-locator")?;
    let fingerprint = required_option(arguments, "--peer-fingerprint")?;
    let ice_mode = match option(arguments, "--ice-mode")
        .as_deref()
        .unwrap_or("automatic")
    {
        "automatic" => IceMode::Automatic,
        "relay-only" => IceMode::RelayOnlyDiagnostic,
        _ => return Err("--ice-mode must be automatic or relay-only".into()),
    };
    Ok(FileSessionConfig {
        coordinator_url,
        peer: PeerReference {
            locator,
            fingerprint,
        },
        ice_mode,
        stun_urls: options(arguments, "--stun"),
        bind_address: option(arguments, "--bind").unwrap_or_else(|| "0.0.0.0:0".into()),
        local_test_skip_turn_transport: arguments
            .iter()
            .any(|argument| argument == "--local-test-skip-turn-transport"),
    })
}

fn ssh_config(arguments: &[String]) -> Result<SshSessionConfig, String> {
    let coordinator_url = required_option(arguments, "--coordinator")?;
    let locator = required_option(arguments, "--peer-locator")?;
    let fingerprint = required_option(arguments, "--peer-fingerprint")?;
    let username = required_option(arguments, "--username")?;
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "--username must contain only letters, digits, dot, underscore or hyphen".into(),
        );
    }
    let ice_mode = match option(arguments, "--ice-mode")
        .as_deref()
        .unwrap_or("automatic")
    {
        "automatic" => IceMode::Automatic,
        "relay-only" => IceMode::RelayOnlyDiagnostic,
        _ => return Err("--ice-mode must be automatic or relay-only".into()),
    };
    Ok(SshSessionConfig {
        coordinator_url,
        peer: PeerReference {
            locator,
            fingerprint,
        },
        ice_mode,
        stun_urls: options(arguments, "--stun"),
        bind_address: option(arguments, "--bind").unwrap_or_else(|| "0.0.0.0:0".into()),
        username,
    })
}

fn desktop_command_reader() -> (mpsc::Sender<DesktopCommand>, mpsc::Receiver<DesktopCommand>) {
    let (sender, receiver) = mpsc::channel(32);
    let reader_sender = sender.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.len() > 2_048 {
                continue;
            }
            if let Ok(command) = serde_json::from_str::<DesktopCommand>(&line) {
                if reader_sender.send(command).await.is_err() {
                    break;
                }
            }
        }
    });
    (sender, receiver)
}

fn file_command_reader() -> (mpsc::Sender<FileCommand>, mpsc::Receiver<FileCommand>) {
    let (sender, receiver) = mpsc::channel(32);
    let reader_sender = sender.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.len() > 4_096 {
                continue;
            }
            if let Ok(command) = serde_json::from_str::<FileCommand>(&line) {
                if reader_sender.send(command).await.is_err() {
                    break;
                }
            }
        }
    });
    (sender, receiver)
}

fn ssh_command_reader() -> (mpsc::Sender<SshCommand>, mpsc::Receiver<SshCommand>) {
    let (sender, receiver) = mpsc::channel(64);
    let reader_sender = sender.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.len() > 24_000 {
                continue;
            }
            if let Ok(command) = serde_json::from_str::<SshCommand>(&line) {
                if reader_sender.send(command).await.is_err() {
                    break;
                }
            }
        }
    });
    (sender, receiver)
}

async fn print_desktop_events(mut events: mpsc::Receiver<DesktopEvent>) {
    while let Some(event) = events.recv().await {
        if let Ok(value) = serde_json::to_string(&event) {
            println!("{value}");
        }
    }
}

async fn print_file_events(mut events: mpsc::Receiver<FileEvent>) {
    while let Some(event) = events.recv().await {
        if let Ok(value) = serde_json::to_string(&event) {
            println!("{value}");
        }
    }
}

async fn print_ssh_events(mut events: mpsc::Receiver<SshEvent>) {
    while let Some(event) = events.recv().await {
        if let Ok(value) = serde_json::to_string(&event) {
            println!("{value}");
        }
    }
}

/// This is intentionally a small public vocabulary. Electron never receives
/// raw coordinator, WebRTC, OS-permission, identity, or filesystem errors.
fn desktop_failure_code(error: &AgentError) -> &'static str {
    match error {
        AgentError::SessionAuthorizationDenied | AgentError::UnattendedAccessDisabled => {
            "authorization_denied"
        }
        AgentError::DesktopControlDenied => "control_denied",
        AgentError::DesktopCapabilityUnavailable(_) => "capability_unavailable",
        AgentError::SessionTimedOut => "timeout",
        AgentError::WebRtc(_) => "transport_failed",
        AgentError::CoordinatorDenied(_) => "coordinator_denied",
        AgentError::CoordinatorProtocol(_)
        | AgentError::InvalidSessionEnvelope
        | AgentError::SessionIdentityOrFreshnessDenied
        | AgentError::SessionReplayDenied
        | AgentError::InvalidDesktopMessage => "protocol_rejected",
        _ => "native_session_failed",
    }
}

fn file_failure_code(error: &AgentError) -> &'static str {
    match error {
        AgentError::SessionAuthorizationDenied | AgentError::UnattendedAccessDisabled => {
            "authorization_denied"
        }
        AgentError::FileTransfer(_) => "file_operation_rejected",
        AgentError::SessionTimedOut => "timeout",
        AgentError::WebRtc(_) => "transport_failed",
        AgentError::CoordinatorDenied(_) => "coordinator_denied",
        AgentError::CoordinatorProtocol(_)
        | AgentError::InvalidSessionEnvelope
        | AgentError::SessionIdentityOrFreshnessDenied
        | AgentError::SessionReplayDenied => "protocol_rejected",
        _ => "native_session_failed",
    }
}

fn ssh_failure_code(error: &AgentError) -> &'static str {
    match error {
        AgentError::SessionAuthorizationDenied | AgentError::UnattendedAccessDisabled => {
            "authorization_denied"
        }
        AgentError::SshUnavailable(_) => "ssh_unavailable",
        AgentError::SessionTimedOut => "timeout",
        AgentError::WebRtc(_) => "transport_failed",
        AgentError::CoordinatorDenied(_) => "coordinator_denied",
        AgentError::CoordinatorProtocol(_)
        | AgentError::InvalidSessionEnvelope
        | AgentError::SessionIdentityOrFreshnessDenied
        | AgentError::SessionReplayDenied => "protocol_rejected",
        _ => "native_session_failed",
    }
}

#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("init") | Some("status") => match AgentStore::open(state_dir(&arguments)) {
            Ok(mut store) => match store.load_or_create_identity() {
                Ok(identity) => {
                    let public = public_identity(&identity);
                    let trusted_devices = store.trusted_device_count().unwrap_or(0);
                    let unattended = store.unattended_status().ok();
                    println!(
                        "{{\"phase\":\"operational-unattended-access\",\"os\":\"{}\",\"arch\":\"{}\",\"device_locator\":\"{}\",\"fingerprint\":\"{}\",\"trusted_devices\":{},\"unattended\":{},\"unattended_scopes\":{},\"active_unattended_sessions\":{},\"remote_access\":false}}",
                        std::env::consts::OS,
                        std::env::consts::ARCH,
                        public.locator,
                        public.fingerprint,
                        trusted_devices,
                        unattended.as_ref().is_some_and(|status| status.enabled),
                        serde_json::to_string(&unattended.as_ref().map(|status| &status.allowed_capabilities).cloned().unwrap_or_default()).unwrap_or_else(|_| "[]".into()),
                        unattended.map(|status| status.active_sessions).unwrap_or(0),
                    );
                }
                Err(error) => {
                    eprintln!("Agent identity unavailable: {error}");
                    std::process::exit(1);
                }
            },
            Err(error) => {
                eprintln!("Agent store unavailable: {error}");
                std::process::exit(1);
            }
        },
        Some("daemon") => {
            let directory = state_dir(&arguments);
            match AgentStore::open(&directory) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(_) => {
                        let recovered = store
                            .recover_stale_sessions(now_millis().unwrap_or(0))
                            .unwrap_or(0);
                        println!("{{\"service\":\"ready\",\"localControl\":\"{}\",\"recoveredStaleSessions\":{}}}", socket_path(&directory).display(), recovered);
                        if let Err(error) = run_daemon(directory, coordinator_url(&arguments)).await
                        {
                            eprintln!("Local control service failed: {error}");
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("local-control") => {
            let request = match local_control_request(&arguments) {
                Ok(request) => request,
                Err(error) => {
                    eprintln!("local-control: {error}");
                    std::process::exit(2);
                }
            };
            match local_control_client(state_dir(&arguments), request).await {
                Ok(response) if response.ok => match serde_json::to_string(&response) {
                    Ok(value) => println!("{value}"),
                    Err(_) => std::process::exit(1),
                },
                Ok(_) => {
                    eprintln!("Local control request rejected");
                    std::process::exit(1);
                }
                Err(error) => {
                    eprintln!("Local control unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("enable-unattended") => {
            if option(&arguments, "--owner-confirmation").as_deref() != Some("ENABLE_UNATTENDED") {
                eprintln!("enable-unattended requires --owner-confirmation ENABLE_UNATTENDED after local review");
                std::process::exit(2);
            }
            let capabilities = options(&arguments, "--allow")
                .iter()
                .map(|value| {
                    unattended_capability(value)
                        .ok_or_else(|| format!("unknown unattended capability: {value}"))
                })
                .collect::<Result<Vec<_>, _>>();
            let capabilities = match capabilities {
                Ok(capabilities) if !capabilities.is_empty() => capabilities,
                Ok(_) => {
                    eprintln!("enable-unattended requires one or more --allow scoped capabilities");
                    std::process::exit(2);
                }
                Err(error) => {
                    eprintln!("enable-unattended: {error}");
                    std::process::exit(2);
                }
            };
            if let Err(error) = verify_unattended_permissions(&capabilities) {
                eprintln!("Required OS permissions are unavailable: {error}");
                std::process::exit(1);
            }
            let Some(now) = now_millis() else {
                eprintln!("System clock unavailable");
                std::process::exit(1);
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store
                    .load_or_create_identity()
                    .and_then(|_| store.enable_unattended(&capabilities, now))
                    .and_then(|_| store.unattended_status())
                {
                    Ok(status) => println!(
                        "{}",
                        serde_json::to_string(&status).unwrap_or_else(|_| "{}".into())
                    ),
                    Err(error) => {
                        eprintln!("Unattended enable failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("disable-unattended") => {
            if option(&arguments, "--owner-confirmation").as_deref() != Some("DISABLE_UNATTENDED") {
                eprintln!("disable-unattended requires --owner-confirmation DISABLE_UNATTENDED");
                std::process::exit(2);
            }
            let Some(now) = now_millis() else {
                eprintln!("System clock unavailable");
                std::process::exit(1);
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store
                    .disable_unattended(now, "local_owner_disabled")
                    .and_then(|_| store.unattended_status())
                {
                    Ok(status) => println!(
                        "{}",
                        serde_json::to_string(&status).unwrap_or_else(|_| "{}".into())
                    ),
                    Err(error) => {
                        eprintln!("Unattended disable failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("trusted-devices") | Some("security-events") => {
            let limit = option(&arguments, "--limit")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(50);
            match AgentStore::open(state_dir(&arguments)) {
                Ok(store) => {
                    let records = if arguments
                        .first()
                        .is_some_and(|command| command == "trusted-devices")
                    {
                        store.trusted_devices().and_then(|devices| {
                            serde_json::to_string(&devices)
                                .map_err(|_| AgentError::IdentityInconsistent)
                        })
                    } else {
                        store.security_events(limit).and_then(|events| {
                            serde_json::to_string(&events)
                                .map_err(|_| AgentError::IdentityInconsistent)
                        })
                    };
                    match records {
                        Ok(value) => println!("{value}"),
                        Err(error) => {
                            eprintln!("Read failed: {error}");
                            std::process::exit(1);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("revoke-peer") => {
            let Ok(fingerprint) = required_option(&arguments, "--peer-fingerprint") else {
                eprintln!("revoke-peer requires --peer-fingerprint FINGERPRINT");
                std::process::exit(2);
            };
            let Some(now) = now_millis() else {
                eprintln!("System clock unavailable");
                std::process::exit(1);
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.revoke_peer(&fingerprint, now) {
                    Ok(()) => println!(
                        "{{\"revoked\":true,\"peerFingerprint\":\"{}\"}}",
                        fingerprint
                    ),
                    Err(error) => {
                        eprintln!("Revocation failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("remote-revoke-peer") => {
            let Some(url) = coordinator_url(&arguments) else {
                eprintln!("remote-revoke-peer requires --coordinator wss://host/v1/connect");
                std::process::exit(2);
            };
            let Ok(locator) = required_option(&arguments, "--peer-locator") else {
                eprintln!("remote-revoke-peer requires --peer-locator LOCATOR and --peer-fingerprint FINGERPRINT");
                std::process::exit(2);
            };
            let Ok(fingerprint) = required_option(&arguments, "--peer-fingerprint") else {
                eprintln!("remote-revoke-peer requires --peer-locator LOCATOR and --peer-fingerprint FINGERPRINT");
                std::process::exit(2);
            };
            match request_remote_revocation(
                state_dir(&arguments),
                &url,
                PeerReference {
                    locator,
                    fingerprint,
                },
            )
            .await
            {
                Ok(result) => println!(
                    "{}",
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
                ),
                Err(error) => {
                    eprintln!(
                        "Remote revocation remains pending until host acknowledgement: {error}"
                    );
                    std::process::exit(1);
                }
            }
        }
        Some("coordinator-status") => {
            let Some(url) = coordinator_url(&arguments) else {
                eprintln!("coordinator-status requires --coordinator wss://host/v1/connect (or WII_COORDINATOR_URL)");
                std::process::exit(2);
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => {
                        match AuthenticatedCoordinator::connect(&url, &identity).await {
                            Ok(connection) => {
                                println!(
                                "{{\"phase\":\"authenticated-connectivity\",\"coordinator\":\"authenticated\",\"session_expires_at\":{},\"remote_access\":false}}",
                                connection.session_expires_at
                            );
                                if let Err(error) = connection.close().await {
                                    eprintln!("Coordinator close failed: {error}");
                                    std::process::exit(1);
                                }
                            }
                            Err(error) => {
                                eprintln!("Coordinator authentication unavailable: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("pair-host") => {
            let Some(url) = coordinator_url(&arguments) else {
                eprintln!("pair-host requires --coordinator wss://host/v1/connect");
                std::process::exit(2);
            };
            let display_name =
                option(&arguments, "--name").unwrap_or_else(|| "Paired controller".into());
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => match host_pair(&mut store, &identity, &url, display_name).await {
                        Ok(result) => println!("{{\"pairing\":\"trusted\",\"peerLocator\":\"{}\",\"peerFingerprint\":\"{}\",\"sas\":\"{}\",\"grantCreated\":false}}", result.peer.locator, result.peer.fingerprint, result.sas),
                        Err(error) => { eprintln!("Pairing failed: {error}"); std::process::exit(1); }
                    },
                    Err(error) => { eprintln!("Agent identity unavailable: {error}"); std::process::exit(1); }
                },
                Err(error) => { eprintln!("Agent store unavailable: {error}"); std::process::exit(1); }
            }
        }
        Some("pair-controller") => {
            let Some(url) = coordinator_url(&arguments) else {
                eprintln!("pair-controller requires --coordinator wss://host/v1/connect");
                std::process::exit(2);
            };
            let Ok(token) = required_option(&arguments, "--token") else {
                eprintln!("pair-controller requires --token INVITATION_TOKEN");
                std::process::exit(2);
            };
            let display_name = option(&arguments, "--name").unwrap_or_else(|| "Paired host".into());
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => match controller_pair(&mut store, &identity, &url, &token, display_name).await {
                        Ok(result) => println!("{{\"pairing\":\"trusted\",\"peerLocator\":\"{}\",\"peerFingerprint\":\"{}\",\"sas\":\"{}\",\"grantCreated\":false}}", result.peer.locator, result.peer.fingerprint, result.sas),
                        Err(error) => { eprintln!("Pairing failed: {error}"); std::process::exit(1); }
                    },
                    Err(error) => { eprintln!("Agent identity unavailable: {error}"); std::process::exit(1); }
                },
                Err(error) => { eprintln!("Agent store unavailable: {error}"); std::process::exit(1); }
            }
        }
        Some("grant-desktop-view")
        | Some("grant-desktop-control")
        | Some("grant-ssh")
        | Some("grant-files-read")
        | Some("grant-files-write")
        | Some("grant-files-read-write") => {
            let Ok(fingerprint) = required_option(&arguments, "--peer-fingerprint") else {
                eprintln!("grant requires --peer-fingerprint FINGERPRINT and --expires-at UNIX_MS");
                std::process::exit(2);
            };
            let expires_at =
                option(&arguments, "--expires-at").and_then(|value| value.parse::<u64>().ok());
            let Some(expires_at) = expires_at else {
                eprintln!("grant requires --expires-at UNIX_MS");
                std::process::exit(2);
            };
            let Some(now) = now_millis() else {
                eprintln!("System clock unavailable");
                std::process::exit(1);
            };
            if expires_at <= now || expires_at.saturating_sub(now) > 86_400_000 {
                eprintln!("grant expiry must be future and no more than 24 hours away");
                std::process::exit(2);
            }
            let (grant_name, capabilities) = match arguments.first().map(String::as_str) {
                Some("grant-desktop-control") => (
                    "desktop.view+desktop.control",
                    vec![Capability::DesktopView, Capability::DesktopControl],
                ),
                Some("grant-desktop-view") => ("desktop.view", vec![Capability::DesktopView]),
                Some("grant-ssh") => ("ssh", vec![Capability::Ssh]),
                Some("grant-files-read") => ("files.read", vec![Capability::FilesRead]),
                Some("grant-files-write") => ("files.write", vec![Capability::FilesWrite]),
                Some("grant-files-read-write") => (
                    "files.read+files.write",
                    vec![Capability::FilesRead, Capability::FilesWrite],
                ),
                _ => unreachable!("matched grant command"),
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.replace_grants(
                    &fingerprint,
                    &[Grant {
                        fingerprint: fingerprint.clone(),
                        revoked: false,
                        not_before: now,
                        expires_at,
                        capabilities,
                    }],
                ) {
                    Ok(()) => println!(
                        "{{\"grant\":\"{}\",\"peerFingerprint\":\"{}\",\"expiresAt\":{}}}",
                        grant_name, fingerprint, expires_at
                    ),
                    Err(error) => {
                        eprintln!("Grant failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("configure-file-roots") => {
            let read_roots = options(&arguments, "--read-root");
            let write_roots = options(&arguments, "--write-root");
            if read_roots.is_empty() && write_roots.is_empty() {
                eprintln!("configure-file-roots requires at least one --read-root or --write-root absolute directory");
                std::process::exit(2);
            }
            let config = match FileRootsConfig::canonicalize(&read_roots, &write_roots) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("File root configuration failed: {error}");
                    std::process::exit(1);
                }
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.set_file_roots(config) {
                    Ok(()) => println!("{{\"fileRoots\":\"configured\"}}"),
                    Err(error) => {
                        eprintln!("File root configuration failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("configure-ssh-endpoint") => {
            let port = option(&arguments, "--port")
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|port| *port > 0);
            let Some(port) = port else {
                eprintln!("configure-ssh-endpoint requires --port 1..65535 for a local loopback SSH server");
                std::process::exit(2);
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.set_ssh_endpoint(ApprovedSshEndpoint { port }) {
                    Ok(()) => println!("{{\"sshEndpoint\":\"loopback_configured\"}}"),
                    Err(error) => {
                        eprintln!("SSH endpoint configuration failed: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("desktop-capabilities") => match desktop_capabilities() {
            Ok(capabilities) => match serde_json::to_string(&capabilities) {
                Ok(value) => println!("{value}"),
                Err(_) => {
                    eprintln!("Could not serialize desktop capabilities");
                    std::process::exit(1);
                }
            },
            Err(error) => {
                eprintln!("Desktop capabilities unavailable: {error}");
                std::process::exit(1);
            }
        },
        Some("desktop-capture-probe") | Some("desktop-input-permission-probe") => {
            let monitor_id = option(&arguments, "--monitor")
                .map(|value| {
                    value
                        .parse::<u32>()
                        .map_err(|_| "--monitor must be a numeric native monitor ID".to_string())
                })
                .transpose();
            let Ok(monitor_id) = monitor_id else {
                eprintln!(
                    "desktop probe configuration: --monitor must be a numeric native monitor ID"
                );
                std::process::exit(2);
            };
            match NativeDesktopHost::open(monitor_id) {
                Ok(mut host)
                    if arguments
                        .first()
                        .is_some_and(|command| command == "desktop-input-permission-probe") =>
                {
                    match host.verify_input_permission() {
                        Ok(()) => println!("{{\"input\":\"available\",\"injectedEvent\":false}}"),
                        Err(error) => {
                            eprintln!("Input permission unavailable: {error}");
                            std::process::exit(1);
                        }
                    }
                }
                Ok(host) => match host.capture(QualityMode::LowBandwidth.profile()) {
                    Ok(frame) => println!(
                        "{{\"capture\":\"available\",\"width\":{},\"height\":{},\"jpegBytes\":{}}}",
                        frame.width,
                        frame.height,
                        frame.jpeg.len()
                    ),
                    Err(error) => {
                        eprintln!("Screen capture unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Desktop adapter unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("desktop-controller") | Some("desktop-host") => {
            let role = if arguments
                .first()
                .is_some_and(|command| command == "desktop-controller")
            {
                DesktopSessionRole::Controller
            } else {
                DesktopSessionRole::Host
            };
            let config = match desktop_config(&arguments) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("Desktop session configuration: {error}");
                    std::process::exit(2);
                }
            };
            let unattended = role == DesktopSessionRole::Host
                && arguments.iter().any(|argument| argument == "--unattended");
            match AgentStore::open(state_dir(&arguments)).map(|store| {
                if unattended {
                    store.enforce_unattended()
                } else {
                    store
                }
            }) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => {
                        let (command_sender, mut commands) = desktop_command_reader();
                        let (event_sender, event_receiver) = mpsc::channel(8);
                        let printer = tokio::spawn(print_desktop_events(event_receiver));
                        let session = run_desktop_session(
                            &store,
                            &identity,
                            &config,
                            role,
                            &mut commands,
                            event_sender,
                        );
                        tokio::pin!(session);
                        let result = tokio::select! {
                            result = &mut session => result,
                            signal = tokio::signal::ctrl_c() => match signal {
                                Ok(()) => {
                                    let _ = command_sender.send(DesktopCommand::Disconnect).await;
                                    timeout(std::time::Duration::from_secs(3), &mut session).await.unwrap_or(Err(wii_ultra_desk_agent::AgentError::SessionTimedOut))
                                }
                                Err(error) => Err(wii_ultra_desk_agent::AgentError::Io(error)),
                            }
                        };
                        drop(command_sender);
                        if let Ok(diagnostics) = &result {
                            if let Ok(value) = serde_json::to_string(diagnostics) {
                                println!("{value}");
                            }
                        }
                        let _ = printer.await;
                        if let Err(error) = result {
                            println!(
                                "{{\"type\":\"failure\",\"code\":\"{}\"}}",
                                desktop_failure_code(&error)
                            );
                            eprintln!("Desktop session failed: {error}");
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("ssh-controller") | Some("ssh-host") => {
            let role = if arguments
                .first()
                .is_some_and(|command| command == "ssh-controller")
            {
                SshSessionRole::Controller
            } else {
                SshSessionRole::Host
            };
            let config = match ssh_config(&arguments) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("SSH session configuration: {error}");
                    std::process::exit(2);
                }
            };
            let unattended = role == SshSessionRole::Host
                && arguments.iter().any(|argument| argument == "--unattended");
            match AgentStore::open(state_dir(&arguments)).map(|store| {
                if unattended {
                    store.enforce_unattended()
                } else {
                    store
                }
            }) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => {
                        let (command_sender, mut commands) = ssh_command_reader();
                        let (event_sender, event_receiver) = mpsc::channel(64);
                        let printer = tokio::spawn(print_ssh_events(event_receiver));
                        let session = run_ssh_session(
                            &store,
                            &identity,
                            &config,
                            role,
                            &mut commands,
                            event_sender,
                        );
                        tokio::pin!(session);
                        let result = tokio::select! {
                            result = &mut session => result,
                            signal = tokio::signal::ctrl_c() => match signal {
                                Ok(()) => {
                                    let _ = command_sender.send(SshCommand::Disconnect).await;
                                    timeout(std::time::Duration::from_secs(3), &mut session).await.unwrap_or(Err(wii_ultra_desk_agent::AgentError::SessionTimedOut))
                                }
                                Err(error) => Err(wii_ultra_desk_agent::AgentError::Io(error)),
                            }
                        };
                        drop(command_sender);
                        if let Ok(diagnostics) = &result {
                            if let Ok(value) = serde_json::to_string(diagnostics) {
                                println!("{value}");
                            }
                        }
                        let _ = printer.await;
                        if let Err(error) = result {
                            println!(
                                "{{\"type\":\"failure\",\"code\":\"{}\"}}",
                                ssh_failure_code(&error)
                            );
                            eprintln!("SSH session failed: {error}");
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("file-controller") | Some("file-host") => {
            let role = if arguments
                .first()
                .is_some_and(|command| command == "file-controller")
            {
                FileSessionRole::Controller
            } else {
                FileSessionRole::Host
            };
            let config = match file_config(&arguments) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("File session configuration: {error}");
                    std::process::exit(2);
                }
            };
            let unattended = role == FileSessionRole::Host
                && arguments.iter().any(|argument| argument == "--unattended");
            match AgentStore::open(state_dir(&arguments)).map(|store| {
                if unattended {
                    store.enforce_unattended()
                } else {
                    store
                }
            }) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => {
                        let (command_sender, mut commands) = file_command_reader();
                        let (event_sender, event_receiver) = mpsc::channel(32);
                        let printer = tokio::spawn(print_file_events(event_receiver));
                        let session = run_file_session(
                            &store,
                            &identity,
                            &config,
                            role,
                            &mut commands,
                            event_sender,
                        );
                        tokio::pin!(session);
                        let result = tokio::select! {
                            result = &mut session => result,
                            signal = tokio::signal::ctrl_c() => match signal {
                                Ok(()) => {
                                    let _ = command_sender.send(FileCommand::Disconnect).await;
                                    timeout(std::time::Duration::from_secs(3), &mut session).await.unwrap_or(Err(wii_ultra_desk_agent::AgentError::SessionTimedOut))
                                }
                                Err(error) => Err(wii_ultra_desk_agent::AgentError::Io(error)),
                            }
                        };
                        drop(command_sender);
                        if let Ok(diagnostics) = &result {
                            if let Ok(value) = serde_json::to_string(diagnostics) {
                                println!("{value}");
                            }
                        }
                        let _ = printer.await;
                        if let Err(error) = result {
                            println!(
                                "{{\"type\":\"failure\",\"code\":\"{}\"}}",
                                file_failure_code(&error)
                            );
                            eprintln!("File session failed: {error}");
                            std::process::exit(1);
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("status-initiate") | Some("status-listen") => {
            let role = if arguments
                .first()
                .is_some_and(|command| command == "status-initiate")
            {
                StatusSessionRole::Initiator
            } else {
                StatusSessionRole::Responder
            };
            let config = match status_config(&arguments) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("Status session configuration: {error}");
                    std::process::exit(2);
                }
            };
            match AgentStore::open(state_dir(&arguments)) {
                Ok(mut store) => match store.load_or_create_identity() {
                    Ok(identity) => {
                        match tokio::select! {
                            result = run_status_session(&store, &identity, &config, role) => result,
                            signal = tokio::signal::ctrl_c() => match signal {
                                Ok(()) => Ok(SessionDiagnostics {
                                    state: ConnectionState::Cancelled,
                                    states: vec![ConnectionState::Cancelled],
                                    route: SelectedRoute::Unknown,
                                    session_id: String::new(),
                                    reauthenticated: false,
                                    attempts: 0,
                                    ping_completed: false,
                                }),
                                Err(error) => Err(wii_ultra_desk_agent::AgentError::Io(error)),
                            },
                        } {
                            Ok(diagnostics) => match serde_json::to_string(&diagnostics) {
                                Ok(value) => println!("{value}"),
                                Err(_) => {
                                    eprintln!("Could not serialize session diagnostics");
                                    std::process::exit(1);
                                }
                            },
                            Err(error) => {
                                eprintln!("Status session failed: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Agent identity unavailable: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("Agent store unavailable: {error}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Usage: wii-ultra-desk-agent <init|status|coordinator-status|pair-host|pair-controller|grant-desktop-view|grant-desktop-control|grant-ssh|grant-files-read|grant-files-write|grant-files-read-write|configure-file-roots|configure-ssh-endpoint|status-listen|status-initiate|desktop-capabilities|desktop-capture-probe|desktop-input-permission-probe|desktop-host|desktop-controller|ssh-host|ssh-controller|file-host|file-controller> [options]\nDesktop host/view uses the native authenticated adapter only. SSH and file transfer require explicit host grants plus local endpoint/root configuration.");
            std::process::exit(2);
        }
    }
}
