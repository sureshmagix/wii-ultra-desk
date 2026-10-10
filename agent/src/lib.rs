pub mod coordinator;
pub mod desktop;
pub mod desktop_session;
pub mod file_session;
pub mod identity;
pub mod lifecycle;
pub mod pairing;
pub mod policy;
pub mod secure_file;
pub mod session;
pub mod ssh_session;
pub mod store;
pub mod transport;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("credential store error: {0}")]
    Credential(#[from] keyring::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("identity state is incomplete or inconsistent")]
    IdentityInconsistent,
    #[error("invalid identity material")]
    InvalidIdentityMaterial,
    #[error("a pinned identity cannot be replaced without local revocation")]
    IdentityMismatch,
    #[error("unattended access remains disabled in Phase 2A")]
    UnattendedAccessDisabled,
    #[error("invalid authenticated-session envelope")]
    InvalidSessionEnvelope,
    #[error("session identity or freshness check failed")]
    SessionIdentityOrFreshnessDenied,
    #[error("session replay was rejected")]
    SessionReplayDenied,
    #[error("invalid bounded status message")]
    InvalidStatusMessage,
    #[error("invalid bounded desktop message")]
    InvalidDesktopMessage,
    #[error("desktop capability unavailable: {0}")]
    DesktopCapabilityUnavailable(String),
    #[error("desktop input was denied by host authorization")]
    DesktopControlDenied,
    #[error("file transfer rejected: {0}")]
    FileTransfer(String),
    #[error("SSH session unavailable: {0}")]
    SshUnavailable(String),
    #[error("desktop.view is not authorized for this trusted peer")]
    SessionAuthorizationDenied,
    #[error("attended pairing was denied or did not prove the expected identity")]
    PairingDenied,
    #[error("session timed out while waiting for an authenticated peer")]
    SessionTimedOut,
    #[error("WebRTC transport error: {0}")]
    WebRtc(String),
    #[error("coordinator protocol error: {0}")]
    CoordinatorProtocol(String),
    #[error("coordinator authentication or authorization failed: {0}")]
    CoordinatorDenied(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
