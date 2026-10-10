use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{validate_locator, DeviceIdentity, DeviceIdentityPublic, IdentityBundle};
use crate::policy::{Capability, Grant, CAPABILITIES};
use crate::secure_file::FileRootsConfig;
use crate::{AgentError, Result};

const KEYRING_SERVICE: &str = "org.wii-ultra-desk.agent";
const FILE_ROOTS_METADATA_KEY: &str = "file_roots_v1";
const SSH_ENDPOINT_METADATA_KEY: &str = "ssh_endpoint_v1";
const UNATTENDED_CAPABILITIES_METADATA_KEY: &str = "unattended_capabilities_v1";
const UNATTENDED_EPOCH_METADATA_KEY: &str = "unattended_epoch_v1";
const LAST_WALL_CLOCK_METADATA_KEY: &str = "last_wall_clock_ms_v1";
pub const UNATTENDED_LEASE_MAX_MS: u64 = 5 * 60_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedSshEndpoint {
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct TrustedPeer {
    pub locator: String,
    pub fingerprint: String,
    pub signing_public_key: String,
    pub noise_public_key: String,
    pub display_name: String,
}

impl TrustedPeer {
    /// A trust record may only be derived from a verified identity bundle. The
    /// caller additionally proves this bundle's Noise key in the XX exchange.
    pub fn from_verified_bundle(bundle: &IdentityBundle, display_name: String) -> Result<Self> {
        let public = bundle.verify()?;
        if display_name.trim().is_empty() || display_name.len() > 80 {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        Ok(Self {
            locator: public.locator,
            fingerprint: public.fingerprint,
            signing_public_key: public.signing_public_key,
            noise_public_key: public.noise_public_key,
            display_name,
        })
    }
}

/// Constructed only by the native store after an exact pinned-peer lookup.
/// A caller cannot deserialize or supply one.  A host-side capability check
/// returns the same opaque proof only after it has also checked the scoped
/// grant; a controller may use it to verify a trusted host's signed SDP
/// without thereby granting that host reverse desktop access.
#[derive(Clone, Debug)]
pub struct AuthorizedSessionPeer {
    peer: TrustedPeer,
}

impl AuthorizedSessionPeer {
    pub fn peer(&self) -> &TrustedPeer {
        &self.peer
    }

    #[cfg(test)]
    pub(crate) fn for_test(peer: TrustedPeer) -> Self {
        Self { peer }
    }
}

pub struct AgentStore {
    connection: Connection,
    state_dir: PathBuf,
    keyring_account: String,
    // This is set only by the independently launched background agent.  The
    // interactive Electron path remains attended and must not accidentally
    // become unavailable simply because unattended access is off.
    enforce_unattended: bool,
    observed_clock: Cell<Option<u64>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceSummary {
    pub locator: String,
    pub fingerprint: String,
    pub display_name: String,
    pub paired_at: u64,
    pub revoked: bool,
    pub grants: Vec<GrantSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantSummary {
    pub capability: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: u64,
    pub occurred_at: u64,
    pub event_type: String,
    pub fingerprint: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnattendedStatus {
    pub enabled: bool,
    pub allowed_capabilities: Vec<String>,
    pub epoch: u64,
    pub active_sessions: u64,
}

fn keyring_account(state_dir: &Path) -> String {
    let digest = Sha256::digest(state_dir.to_string_lossy().as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn secret(entry: &Entry) -> Result<Option<Vec<u8>>> {
    match entry.get_secret() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn timestamp(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| AgentError::InvalidIdentityMaterial)
}

fn now_millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::InvalidIdentityMaterial)
        .map(|value| value.as_millis() as u64)
}

impl AgentStore {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        fs::create_dir_all(&state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;
        }
        let connection = Connection::open(state_dir.join("agent.sqlite"))?;
        let mut store = Self {
            keyring_account: keyring_account(&state_dir),
            state_dir,
            connection,
            enforce_unattended: false,
            observed_clock: Cell::new(None),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS trusted_devices (
               fingerprint TEXT PRIMARY KEY,
               locator TEXT NOT NULL UNIQUE,
               signing_public_key TEXT NOT NULL,
               noise_public_key TEXT NOT NULL,
               display_name TEXT NOT NULL,
               paired_at INTEGER NOT NULL,
               revoked_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS grants (
               fingerprint TEXT NOT NULL REFERENCES trusted_devices(fingerprint),
               capability TEXT NOT NULL,
               not_before INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
               PRIMARY KEY(fingerprint, capability)
             );"
        )?;
        let migration: Option<i64> = self
            .connection
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if migration.is_none() {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (1, strftime('%s', 'now') * 1000)", [])?;
            tx.execute(
                "INSERT INTO metadata (key, value) VALUES ('unattended_enabled', 'false')",
                [],
            )?;
            tx.commit()?;
        }
        let migration: Option<i64> = self
            .connection
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if migration.is_none() {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS active_sessions (
                   session_id TEXT PRIMARY KEY,
                   fingerprint TEXT NOT NULL REFERENCES trusted_devices(fingerprint),
                   kind TEXT NOT NULL CHECK(kind IN ('desktop', 'ssh', 'files')),
                   started_at INTEGER NOT NULL,
                   lease_expires_at INTEGER NOT NULL,
                   state TEXT NOT NULL CHECK(state IN ('active', 'terminated', 'stale')),
                   termination_reason TEXT
                 );
                 CREATE TABLE IF NOT EXISTS security_events (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   occurred_at INTEGER NOT NULL,
                   event_type TEXT NOT NULL,
                   fingerprint TEXT,
                   detail TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS remote_revocations (
                   request_id TEXT PRIMARY KEY,
                   fingerprint TEXT NOT NULL,
                   requested_at INTEGER NOT NULL,
                   acknowledged_at INTEGER,
                   state TEXT NOT NULL CHECK(state IN ('pending', 'acknowledged', 'expired'))
                 );",
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO metadata (key, value) VALUES (?, '[]')",
                [UNATTENDED_CAPABILITIES_METADATA_KEY],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO metadata (key, value) VALUES (?, '0')",
                [UNATTENDED_EPOCH_METADATA_KEY],
            )?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (2, strftime('%s', 'now') * 1000)",
                [],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Marks a store as the service-owned unattended boundary.  This is a
    /// construction-time property, so renderer/CLI supplied values cannot
    /// accidentally opt an attended session into background authorization.
    pub fn enforce_unattended(mut self) -> Self {
        self.enforce_unattended = true;
        self
    }

    pub fn unattended_service_mode(&self) -> bool {
        self.enforce_unattended
    }

    fn metadata(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM metadata WHERE key = ?", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    fn append_security_event(
        &self,
        occurred_at: u64,
        event_type: &str,
        fingerprint: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        if event_type.is_empty()
            || event_type.len() > 80
            || !event_type
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit())
            || detail.len() > 160
            || detail.contains('\n')
            || fingerprint.is_some_and(|value| !valid_fingerprint(value))
        {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        self.connection.execute(
            "INSERT INTO security_events (occurred_at, event_type, fingerprint, detail) VALUES (?, ?, ?, ?)",
            params![timestamp(occurred_at)?, event_type, fingerprint, detail],
        )?;
        Ok(())
    }

    fn allowed_unattended_capabilities(&self) -> Result<Vec<String>> {
        let raw = self
            .metadata(UNATTENDED_CAPABILITIES_METADATA_KEY)?
            .unwrap_or_else(|| "[]".into());
        let capabilities: Vec<String> =
            serde_json::from_str(&raw).map_err(|_| AgentError::IdentityInconsistent)?;
        if capabilities.len() > CAPABILITIES.len()
            || capabilities
                .iter()
                .any(|capability| !validate_capability(capability))
            || capabilities.windows(2).any(|window| window[0] >= window[1])
        {
            return Err(AgentError::IdentityInconsistent);
        }
        Ok(capabilities)
    }

    fn unattended_epoch(&self) -> Result<u64> {
        self.metadata(UNATTENDED_EPOCH_METADATA_KEY)?
            .unwrap_or_else(|| "0".into())
            .parse::<u64>()
            .map_err(|_| AgentError::IdentityInconsistent)
    }

    /// Reject large backward wall-clock jumps.  Grant expiry is deliberately
    /// evaluated against wall time, so accepting a rollback would extend a
    /// previously expired authorization. Small NTP corrections remain safe.
    pub fn observe_wall_clock(&self, now: u64) -> Result<()> {
        let persisted = self
            .metadata(LAST_WALL_CLOCK_METADATA_KEY)?
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| AgentError::IdentityInconsistent)
            })
            .transpose()?;
        let prior = self.observed_clock.get().or(persisted);
        if prior.is_some_and(|value| now.saturating_add(5 * 60_000) < value) {
            self.append_security_event(now, "clock_anomaly", None, "backward_wall_clock_jump")?;
            return Err(AgentError::SessionAuthorizationDenied);
        }
        if prior.map_or(true, |value| now > value) {
            self.set_metadata(LAST_WALL_CLOCK_METADATA_KEY, &now.to_string())?;
            self.observed_clock.set(Some(now));
        }
        Ok(())
    }

    fn signing_entry(&self) -> Result<Entry> {
        Ok(Entry::new(
            KEYRING_SERVICE,
            &format!("{}:ed25519", self.keyring_account),
        )?)
    }

    fn noise_entry(&self) -> Result<Entry> {
        Ok(Entry::new(
            KEYRING_SERVICE,
            &format!("{}:noise-x25519", self.keyring_account),
        )?)
    }

    pub fn load_or_create_identity(&mut self) -> Result<DeviceIdentity> {
        let signing_entry = self.signing_entry()?;
        let noise_entry = self.noise_entry()?;
        let signing_secret = secret(&signing_entry)?;
        let noise_secret = secret(&noise_entry)?;
        let locator = self.metadata("device_locator")?;
        match (locator, signing_secret, noise_secret) {
            (None, None, None) => {
                let identity = DeviceIdentity::generate(now_millis()?)?;
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('identity_provisioning', ?)",
                    [&identity.public.locator],
                )?;
                tx.commit()?;
                // Keychain writes cannot participate in a SQLite transaction. A remaining
                // provisioning marker is treated as an error on restart, never as new trust.
                signing_entry.set_secret(&identity.signing_secret())?;
                noise_entry.set_secret(&identity.noise_static_secret())?;
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('device_locator', ?)",
                    [&identity.public.locator],
                )?;
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('signing_public_key', ?)",
                    [&identity.public.signing_public_key],
                )?;
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('noise_public_key', ?)",
                    [&identity.public.noise_public_key],
                )?;
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('identity_created_at', ?)",
                    [identity.public.created_at.to_string()],
                )?;
                tx.execute(
                    "DELETE FROM metadata WHERE key = 'identity_provisioning'",
                    [],
                )?;
                tx.commit()?;
                Ok(identity)
            }
            (Some(locator), Some(signing_secret), Some(noise_secret)) => {
                if self.metadata("identity_provisioning")?.is_some() {
                    return Err(AgentError::IdentityInconsistent);
                }
                let noise_public_key = self
                    .metadata("noise_public_key")?
                    .ok_or(AgentError::IdentityInconsistent)?;
                // Phase 2A identities predate signed coordinator bundles.  The
                // first Phase 2B coordinator connection pins this public
                // creation time locally; it is never changed afterwards.
                let created_at = match self.metadata("identity_created_at")? {
                    Some(value) => value
                        .parse::<u64>()
                        .map_err(|_| AgentError::IdentityInconsistent)?,
                    None => {
                        let value = now_millis()?;
                        self.connection.execute(
                            "INSERT INTO metadata (key, value) VALUES ('identity_created_at', ?)",
                            [value.to_string()],
                        )?;
                        value
                    }
                };
                let identity = DeviceIdentity::from_stored_secrets(
                    locator,
                    signing_secret,
                    noise_secret,
                    noise_public_key,
                    created_at,
                )?;
                if self.metadata("signing_public_key")?.as_deref()
                    != Some(&identity.public.signing_public_key)
                    || self.metadata("noise_public_key")?.as_deref()
                        != Some(&identity.public.noise_public_key)
                {
                    return Err(AgentError::IdentityInconsistent);
                }
                Ok(identity)
            }
            _ => Err(AgentError::IdentityInconsistent),
        }
    }

    pub fn persist_trusted_peer(&mut self, peer: &TrustedPeer, now: u64) -> Result<()> {
        if validate_locator(&peer.locator).is_err()
            || !valid_fingerprint(&peer.fingerprint)
            || peer.display_name.trim().is_empty()
            || peer.display_name.len() > 80
        {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let signing_key = URL_SAFE_NO_PAD
            .decode(&peer.signing_public_key)
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        let noise_key = URL_SAFE_NO_PAD
            .decode(&peer.noise_public_key)
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        if signing_key.len() != 32
            || noise_key.len() != 32
            || URL_SAFE_NO_PAD.encode(&signing_key) != peer.signing_public_key
            || URL_SAFE_NO_PAD.encode(&noise_key) != peer.noise_public_key
            || crate::identity::fingerprint(
                &signing_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| AgentError::InvalidIdentityMaterial)?,
            ) != peer.fingerprint
        {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String)> = tx.query_row(
            "SELECT locator, signing_public_key, noise_public_key FROM trusted_devices WHERE fingerprint = ?",
            [&peer.fingerprint], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).optional()?;
        if let Some((locator, signing, noise)) = existing {
            if locator != peer.locator
                || signing != peer.signing_public_key
                || noise != peer.noise_public_key
            {
                return Err(AgentError::IdentityMismatch);
            }
            tx.execute("UPDATE trusted_devices SET display_name = ?, revoked_at = NULL WHERE fingerprint = ?", params![peer.display_name, peer.fingerprint])?;
        } else {
            tx.execute(
                "INSERT INTO trusted_devices (fingerprint, locator, signing_public_key, noise_public_key, display_name, paired_at) VALUES (?, ?, ?, ?, ?, ?)",
                params![peer.fingerprint, peer.locator, peer.signing_public_key, peer.noise_public_key, peer.display_name, timestamp(now)?]
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_peer(&mut self, fingerprint: &str, now: u64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE trusted_devices SET revoked_at = ? WHERE fingerprint = ? AND revoked_at IS NULL", params![timestamp(now)?, fingerprint])?;
        if changed != 1 {
            return Err(AgentError::IdentityMismatch);
        }
        tx.execute(
            "UPDATE grants SET revoked = 1 WHERE fingerprint = ?",
            [fingerprint],
        )?;
        tx.execute(
            "UPDATE active_sessions SET state = 'terminated', termination_reason = 'peer_revoked' WHERE fingerprint = ? AND state = 'active'",
            [fingerprint],
        )?;
        tx.commit()?;
        self.append_security_event(
            now,
            "trusted_device_revoked",
            Some(fingerprint),
            "all_scopes_revoked",
        )?;
        Ok(())
    }

    /// Enable is intentionally separate from pairing and grants. A local
    /// owner must make this call after platform permission preflight, and must
    /// name the narrow capabilities that may be used while nobody is present.
    pub fn enable_unattended(&mut self, capabilities: &[Capability], now: u64) -> Result<()> {
        if capabilities.is_empty() || capabilities.len() > CAPABILITIES.len() {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        let mut allowed = capabilities
            .iter()
            .map(|capability| capability.as_str().to_string())
            .collect::<Vec<_>>();
        allowed.sort();
        allowed.dedup();
        if allowed.len() != capabilities.len() {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        let encoded =
            serde_json::to_string(&allowed).map_err(|_| AgentError::UnattendedAccessDisabled)?;
        let epoch = self.unattended_epoch()?.saturating_add(1);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO metadata (key, value) VALUES ('unattended_enabled', 'true') ON CONFLICT(key) DO UPDATE SET value = 'true'",
            [],
        )?;
        tx.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![UNATTENDED_CAPABILITIES_METADATA_KEY, encoded],
        )?;
        tx.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![UNATTENDED_EPOCH_METADATA_KEY, epoch.to_string()],
        )?;
        tx.commit()?;
        self.append_security_event(now, "unattended_enabled", None, "local_owner_action")?;
        Ok(())
    }

    /// Disabling is immediate and invalidates every service-owned session.
    /// Session loops observe this state at most once per second and release
    /// their local capture, input, PTY, file, and data-channel resources.
    pub fn disable_unattended(&mut self, now: u64, reason: &str) -> Result<()> {
        if reason.is_empty()
            || reason.len() > 80
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        let epoch = self.unattended_epoch()?.saturating_add(1);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO metadata (key, value) VALUES ('unattended_enabled', 'false') ON CONFLICT(key) DO UPDATE SET value = 'false'",
            [],
        )?;
        tx.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![UNATTENDED_EPOCH_METADATA_KEY, epoch.to_string()],
        )?;
        tx.execute(
            "UPDATE active_sessions SET state = 'terminated', termination_reason = ? WHERE state = 'active'",
            [reason],
        )?;
        tx.commit()?;
        self.append_security_event(now, "unattended_disabled", None, reason)?;
        Ok(())
    }

    pub fn disconnect_unattended_sessions(&self, now: u64, reason: &str) -> Result<u64> {
        if reason.is_empty()
            || reason.len() > 80
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        let changed = self.connection.execute(
            "UPDATE active_sessions SET state = 'terminated', termination_reason = ? WHERE state = 'active'",
            [reason],
        )?;
        if changed > 0 {
            self.append_security_event(now, "unattended_sessions_disconnected", None, reason)?;
        }
        u64::try_from(changed).map_err(|_| AgentError::IdentityInconsistent)
    }

    pub fn unattended_status(&self) -> Result<UnattendedStatus> {
        let active: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM active_sessions WHERE state = 'active'",
            [],
            |row| row.get(0),
        )?;
        Ok(UnattendedStatus {
            enabled: self.unattended_enabled()?,
            allowed_capabilities: self.allowed_unattended_capabilities()?,
            epoch: self.unattended_epoch()?,
            active_sessions: u64::try_from(active).map_err(|_| AgentError::IdentityInconsistent)?,
        })
    }

    pub fn record_unattended_session(
        &self,
        session_id: &str,
        fingerprint: &str,
        kind: &str,
        now: u64,
        lease_expires_at: u64,
    ) -> Result<()> {
        if !self.enforce_unattended
            || !valid_session_id(session_id)
            || !valid_fingerprint(fingerprint)
            || !matches!(kind, "desktop" | "ssh" | "files")
            || lease_expires_at <= now
            || lease_expires_at.saturating_sub(now) > UNATTENDED_LEASE_MAX_MS
        {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        self.observe_wall_clock(now)?;
        if !self.unattended_enabled()? {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        self.connection.execute(
            "INSERT INTO active_sessions (session_id, fingerprint, kind, started_at, lease_expires_at, state) VALUES (?, ?, ?, ?, ?, 'active')",
            params![session_id, fingerprint, kind, timestamp(now)?, timestamp(lease_expires_at)?],
        )?;
        self.append_security_event(now, "unattended_session_started", Some(fingerprint), kind)
    }

    pub fn close_unattended_session(&self, session_id: &str, now: u64, reason: &str) -> Result<()> {
        if session_id.len() != 22 || reason.is_empty() || reason.len() > 80 {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        self.connection.execute(
            "UPDATE active_sessions SET state = 'terminated', termination_reason = ? WHERE session_id = ? AND state = 'active'",
            params![reason, session_id],
        )?;
        self.append_security_event(now, "unattended_session_ended", None, reason)
    }

    pub fn unattended_session_current(
        &self,
        session_id: &str,
        locator: &str,
        fingerprint: &str,
        capability: Capability,
        now: u64,
    ) -> Result<()> {
        self.authorize_desktop_session(locator, fingerprint, capability, now)?;
        if !self.enforce_unattended {
            return Ok(());
        }
        let current: Option<i64> = self.connection.query_row(
            "SELECT 1 FROM active_sessions WHERE session_id = ? AND fingerprint = ? AND state = 'active' AND lease_expires_at > ?",
            params![session_id, fingerprint, timestamp(now)?],
            |row| row.get(0),
        ).optional()?;
        if current.is_none() {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        Ok(())
    }

    pub fn unattended_session_lease_current(
        &self,
        session_id: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<()> {
        if !self.enforce_unattended {
            return Ok(());
        }
        self.observe_wall_clock(now)?;
        if !self.unattended_enabled()? {
            return Err(AgentError::UnattendedAccessDisabled);
        }
        let current: Option<i64> = self.connection.query_row(
            "SELECT 1 FROM active_sessions WHERE session_id = ? AND fingerprint = ? AND state = 'active' AND lease_expires_at > ?",
            params![session_id, fingerprint, timestamp(now)?],
            |row| row.get(0),
        ).optional()?;
        if current.is_none() {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        Ok(())
    }

    /// A daemon restart cannot leave a stale record looking live. The actual
    /// process has gone away, so its OS resources have already been reclaimed.
    pub fn recover_stale_sessions(&mut self, now: u64) -> Result<u64> {
        let changed = self.connection.execute(
            "UPDATE active_sessions SET state = 'stale', termination_reason = 'agent_restarted' WHERE state = 'active'",
            [],
        )?;
        if changed > 0 {
            self.append_security_event(now, "stale_sessions_recovered", None, "agent_restarted")?;
        }
        u64::try_from(changed).map_err(|_| AgentError::IdentityInconsistent)
    }

    pub fn trusted_devices(&self) -> Result<Vec<TrustedDeviceSummary>> {
        let mut statement = self.connection.prepare(
            "SELECT locator, fingerprint, display_name, paired_at, revoked_at FROM trusted_devices ORDER BY paired_at DESC, fingerprint",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        let mut devices = Vec::new();
        for row in rows {
            let (locator, fingerprint, display_name, paired_at, revoked_at) = row?;
            let mut grants = self.connection.prepare(
                "SELECT capability, not_before, expires_at, revoked FROM grants WHERE fingerprint = ? ORDER BY capability",
            )?;
            let grants = grants
                .query_map([&fingerprint], |row| {
                    Ok(GrantSummary {
                        capability: row.get(0)?,
                        not_before: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                        expires_at: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                        revoked: row.get::<_, i64>(3)? != 0,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            devices.push(TrustedDeviceSummary {
                locator,
                fingerprint,
                display_name,
                paired_at: u64::try_from(paired_at)
                    .map_err(|_| AgentError::IdentityInconsistent)?,
                revoked: revoked_at.is_some(),
                grants,
            });
        }
        Ok(devices)
    }

    pub fn security_events(&self, limit: u32) -> Result<Vec<SecurityEvent>> {
        if limit == 0 || limit > 200 {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let mut statement = self.connection.prepare(
            "SELECT id, occurred_at, event_type, fingerprint, detail FROM security_events ORDER BY id DESC LIMIT ?",
        )?;
        let events = statement
            .query_map([i64::from(limit)], |row| {
                Ok(SecurityEvent {
                    id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                    occurred_at: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    event_type: row.get(2)?,
                    fingerprint: row.get(3)?,
                    detail: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into);
        events
    }

    /// The requesting controller stays in `pending` until this exact request
    /// ID is acknowledged by the host. A coordinator receipt is not treated as
    /// revocation: it cannot prove that the host terminated its channels.
    pub fn request_remote_revocation(
        &self,
        request_id: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<()> {
        if request_id.len() != 22
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || !valid_fingerprint(fingerprint)
        {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        self.connection.execute(
            "INSERT INTO remote_revocations (request_id, fingerprint, requested_at, state) VALUES (?, ?, ?, 'pending')",
            params![request_id, fingerprint, timestamp(now)?],
        )?;
        self.append_security_event(
            now,
            "remote_revocation_pending",
            Some(fingerprint),
            "awaiting_host_ack",
        )
    }

    pub fn acknowledge_remote_revocation(
        &mut self,
        request_id: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<()> {
        if request_id.len() != 22 || !valid_fingerprint(fingerprint) {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let changed = self.connection.execute(
            "UPDATE remote_revocations SET state = 'acknowledged', acknowledged_at = ? WHERE request_id = ? AND fingerprint = ? AND state = 'pending'",
            params![timestamp(now)?, request_id, fingerprint],
        )?;
        if changed != 1 {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        self.append_security_event(
            now,
            "remote_revocation_acknowledged",
            Some(fingerprint),
            "host_confirmed",
        )
    }

    pub fn expire_pending_remote_revocations(&self, now: u64) -> Result<u64> {
        let changed = self.connection.execute(
            "UPDATE remote_revocations SET state = 'expired' WHERE state = 'pending' AND requested_at <= ?",
            [timestamp(now.saturating_sub(UNATTENDED_LEASE_MAX_MS))?],
        )?;
        u64::try_from(changed).map_err(|_| AgentError::IdentityInconsistent)
    }

    /// Grants can be persisted while unattended access remains disabled. There
    /// is deliberately no Phase 2A API that flips the global enable flag.
    pub fn replace_grants(&mut self, fingerprint: &str, grants: &[Grant]) -> Result<()> {
        if !valid_fingerprint(fingerprint)
            || grants.iter().any(|grant| {
                grant.fingerprint != fingerprint
                    || grant.not_before >= grant.expires_at
                    || grant
                        .capabilities
                        .iter()
                        .any(|capability| !validate_capability(capability.as_str()))
            })
        {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let trusted: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM trusted_devices WHERE fingerprint = ? AND revoked_at IS NULL",
                [fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        if trusted.is_none() {
            return Err(AgentError::IdentityMismatch);
        }
        tx.execute("DELETE FROM grants WHERE fingerprint = ?", [fingerprint])?;
        for grant in grants {
            for capability in &grant.capabilities {
                tx.execute(
                    "INSERT INTO grants (fingerprint, capability, not_before, expires_at, revoked) VALUES (?, ?, ?, ?, ?)",
                    params![fingerprint, capability.as_str(), timestamp(grant.not_before)?, timestamp(grant.expires_at)?, i64::from(grant.revoked)]
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn grant_count(&self, fingerprint: &str) -> Result<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM grants WHERE fingerprint = ?",
            [fingerprint],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| AgentError::InvalidIdentityMaterial)
    }

    /// Check the persisted exact identity and an active scoped capability.
    /// Only native session code can obtain this opaque peer reference; callers
    /// cannot construct a successful authorization with a boolean flag.
    pub fn authorize_desktop_session(
        &self,
        locator: &str,
        fingerprint: &str,
        capability: Capability,
        now: u64,
    ) -> Result<AuthorizedSessionPeer> {
        if self.enforce_unattended {
            self.observe_wall_clock(now)?;
            if !self.unattended_enabled()?
                || !self
                    .allowed_unattended_capabilities()?
                    .iter()
                    .any(|allowed| allowed == capability.as_str())
            {
                return Err(AgentError::UnattendedAccessDisabled);
            }
        }
        let authorized = self.trusted_session_peer(locator, fingerprint)?;
        let timestamp = timestamp(now)?;
        let granted: Option<i64> = self.connection.query_row(
            "SELECT 1 FROM grants WHERE fingerprint = ? AND capability = ? AND revoked = 0 AND not_before <= ? AND expires_at > ?",
            params![fingerprint, capability.as_str(), timestamp, timestamp],
            |row| row.get(0),
        ).optional()?;
        if granted.is_none() {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        Ok(authorized)
    }

    /// Return only a current, pinned and non-revoked peer identity for
    /// session-envelope signature verification.  This intentionally does not
    /// inspect a desktop grant: a controller verifying a host must not need to
    /// issue that host a reverse-access grant.
    pub fn trusted_session_peer(
        &self,
        locator: &str,
        fingerprint: &str,
    ) -> Result<AuthorizedSessionPeer> {
        if locator.len() != 22 || !valid_fingerprint(fingerprint) {
            return Err(AgentError::SessionAuthorizationDenied);
        }
        let peer = self.connection.query_row(
            "SELECT locator, fingerprint, signing_public_key, noise_public_key, display_name FROM trusted_devices WHERE locator = ? AND fingerprint = ? AND revoked_at IS NULL",
            params![locator, fingerprint],
            |row| Ok(TrustedPeer {
                locator: row.get(0)?,
                fingerprint: row.get(1)?,
                signing_public_key: row.get(2)?,
                noise_public_key: row.get(3)?,
                display_name: row.get(4)?,
            }),
        ).optional()?;
        let Some(peer) = peer else {
            return Err(AgentError::SessionAuthorizationDenied);
        };
        Ok(AuthorizedSessionPeer { peer })
    }

    /// A pixel session requires `desktop.view` and never implies control.
    pub fn authorize_desktop_view_session(
        &self,
        locator: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<AuthorizedSessionPeer> {
        self.authorize_desktop_session(locator, fingerprint, Capability::DesktopView, now)
    }

    /// Input is separately authorized at the host on every input message.
    pub fn authorize_desktop_control_session(
        &self,
        locator: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<AuthorizedSessionPeer> {
        self.authorize_desktop_session(locator, fingerprint, Capability::DesktopControl, now)
    }

    pub fn unattended_enabled(&self) -> Result<bool> {
        Ok(self.metadata("unattended_enabled")?.as_deref() == Some("true"))
    }

    /// Configure host-local roots only through the native agent. Stored paths
    /// are already canonical and later reopened through capability handles.
    pub fn set_file_roots(&mut self, config: FileRootsConfig) -> Result<()> {
        let encoded = serde_json::to_string(&config)
            .map_err(|_| AgentError::FileTransfer("root_configuration_invalid".into()))?;
        self.connection.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![FILE_ROOTS_METADATA_KEY, encoded],
        )?;
        Ok(())
    }

    pub fn file_roots(&self) -> Result<FileRootsConfig> {
        let encoded = self
            .metadata(FILE_ROOTS_METADATA_KEY)?
            .ok_or_else(|| AgentError::FileTransfer("roots_not_configured".into()))?;
        let config: FileRootsConfig = serde_json::from_str(&encoded)
            .map_err(|_| AgentError::FileTransfer("root_configuration_invalid".into()))?;
        if config.read_roots.len() > crate::secure_file::MAX_FILE_ROOTS
            || config.write_roots.len() > crate::secure_file::MAX_FILE_ROOTS
        {
            return Err(AgentError::FileTransfer(
                "root_configuration_invalid".into(),
            ));
        }
        Ok(config)
    }

    /// The SSH tunnel can target only an explicitly configured loopback SSH
    /// server on this device. It cannot be repurposed as a network proxy.
    pub fn set_ssh_endpoint(&mut self, endpoint: ApprovedSshEndpoint) -> Result<()> {
        if endpoint.port == 0 {
            return Err(AgentError::SshUnavailable("endpoint_port_invalid".into()));
        }
        let encoded = serde_json::to_string(&endpoint)
            .map_err(|_| AgentError::SshUnavailable("endpoint_invalid".into()))?;
        self.connection.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SSH_ENDPOINT_METADATA_KEY, encoded],
        )?;
        Ok(())
    }

    pub fn ssh_endpoint(&self) -> Result<ApprovedSshEndpoint> {
        let encoded = self
            .metadata(SSH_ENDPOINT_METADATA_KEY)?
            .ok_or_else(|| AgentError::SshUnavailable("endpoint_not_configured".into()))?;
        let endpoint: ApprovedSshEndpoint = serde_json::from_str(&encoded)
            .map_err(|_| AgentError::SshUnavailable("endpoint_invalid".into()))?;
        if endpoint.port == 0 {
            return Err(AgentError::SshUnavailable("endpoint_invalid".into()));
        }
        Ok(endpoint)
    }

    pub fn trusted_device_count(&self) -> Result<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM trusted_devices WHERE revoked_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| AgentError::InvalidIdentityMaterial)
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}

#[allow(dead_code)]
fn validate_capability(capability: &str) -> bool {
    CAPABILITIES.contains(&capability)
}

pub fn public_identity(identity: &DeviceIdentity) -> DeviceIdentityPublic {
    identity.public.clone()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::policy::Capability;

    fn temporary_state_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("wii-ultra-desk-store-{nonce}"))
    }

    fn peer() -> TrustedPeer {
        let identity = DeviceIdentity::generate(1).expect("peer identity");
        TrustedPeer {
            locator: identity.public.locator,
            fingerprint: identity.public.fingerprint,
            signing_public_key: identity.public.signing_public_key,
            noise_public_key: identity.public.noise_public_key,
            display_name: "Development peer".into(),
        }
    }

    #[test]
    fn phase_four_database_migrates_to_default_off_lifecycle_schema() {
        let state_dir = temporary_state_dir();
        fs::create_dir_all(&state_dir).expect("legacy state directory");
        let legacy = Connection::open(state_dir.join("agent.sqlite")).expect("legacy database");
        legacy
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
                 CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE trusted_devices (
                   fingerprint TEXT PRIMARY KEY,
                   locator TEXT NOT NULL UNIQUE,
                   signing_public_key TEXT NOT NULL,
                   noise_public_key TEXT NOT NULL,
                   display_name TEXT NOT NULL,
                   paired_at INTEGER NOT NULL,
                   revoked_at INTEGER
                 );
                 CREATE TABLE grants (
                   fingerprint TEXT NOT NULL REFERENCES trusted_devices(fingerprint),
                   capability TEXT NOT NULL,
                   not_before INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
                   PRIMARY KEY(fingerprint, capability)
                 );
                 INSERT INTO schema_migrations (version, applied_at) VALUES (1, 1);
                 INSERT INTO metadata (key, value) VALUES ('unattended_enabled', 'false');",
            )
            .expect("legacy schema");
        drop(legacy);

        let store = AgentStore::open(&state_dir).expect("migrates legacy database");
        assert!(!store.unattended_status().expect("status").enabled);
        let migration: i64 = store
            .connection
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .expect("migration v2 is recorded");
        assert_eq!(migration, 2);
        fs::remove_dir_all(state_dir).expect("temporary state cleaned");
    }

    #[test]
    fn trust_and_grants_persist_atomically_and_revocation_disables_the_peer() {
        let state_dir = temporary_state_dir();
        let peer = peer();
        {
            let mut store = AgentStore::open(&state_dir).expect("store opens");
            store
                .persist_trusted_peer(&peer, 1_000)
                .expect("trust persists");
            let grant = Grant {
                fingerprint: peer.fingerprint.clone(),
                revoked: false,
                not_before: 100,
                expires_at: 2_000,
                capabilities: vec![Capability::DesktopView, Capability::FilesRead],
            };
            store
                .replace_grants(&peer.fingerprint, &[grant])
                .expect("grants persist atomically");
            assert_eq!(store.trusted_device_count().expect("count"), 1);
            assert_eq!(
                store.grant_count(&peer.fingerprint).expect("grant count"),
                2
            );
            assert!(store
                .authorize_desktop_session(
                    &peer.locator,
                    &peer.fingerprint,
                    Capability::FilesRead,
                    1_000
                )
                .is_ok());
            assert!(matches!(
                store.authorize_desktop_session(
                    &peer.locator,
                    &peer.fingerprint,
                    Capability::FilesWrite,
                    1_000
                ),
                Err(AgentError::SessionAuthorizationDenied)
            ));
            assert!(!store.unattended_enabled().expect("default is available"));
            assert!(store
                .authorize_desktop_view_session(&peer.locator, &peer.fingerprint, 1_000)
                .is_ok());
            assert!(matches!(
                store.authorize_desktop_control_session(&peer.locator, &peer.fingerprint, 1_000),
                Err(AgentError::SessionAuthorizationDenied)
            ));
            store
                .replace_grants(
                    &peer.fingerprint,
                    &[Grant {
                        fingerprint: peer.fingerprint.clone(),
                        revoked: false,
                        not_before: 100,
                        expires_at: 2_000,
                        capabilities: vec![Capability::DesktopView, Capability::DesktopControl],
                    }],
                )
                .expect("control grant persists atomically");
            assert!(store
                .authorize_desktop_control_session(&peer.locator, &peer.fingerprint, 1_000)
                .is_ok());
        }
        {
            let mut store = AgentStore::open(&state_dir).expect("store reopens");
            assert_eq!(
                store
                    .trusted_device_count()
                    .expect("trust survived restart"),
                1
            );
            assert_eq!(
                store
                    .grant_count(&peer.fingerprint)
                    .expect("grants survived restart"),
                2
            );
            store
                .revoke_peer(&peer.fingerprint, 2_000)
                .expect("revocation persists");
            assert!(matches!(
                store.authorize_desktop_view_session(&peer.locator, &peer.fingerprint, 2_000),
                Err(AgentError::SessionAuthorizationDenied)
            ));
            assert_eq!(
                store.trusted_device_count().expect("revoked peer excluded"),
                0
            );
            assert_eq!(
                store
                    .grant_count(&peer.fingerprint)
                    .expect("grants remain auditable"),
                2
            );
        }
        fs::remove_dir_all(state_dir).expect("temporary state cleaned");
    }

    #[test]
    fn pinned_peer_verification_does_not_create_a_desktop_grant() {
        let state_dir = temporary_state_dir();
        let peer = peer();
        let mut store = AgentStore::open(&state_dir).expect("store opens");
        store
            .persist_trusted_peer(&peer, 1_000)
            .expect("trust persists");

        // A controller may validate this peer's signed SDP without issuing a
        // grant that would authorize that peer to view its own desktop.
        assert!(store
            .trusted_session_peer(&peer.locator, &peer.fingerprint)
            .is_ok());
        assert!(matches!(
            store.authorize_desktop_view_session(&peer.locator, &peer.fingerprint, 1_000),
            Err(AgentError::SessionAuthorizationDenied)
        ));

        store
            .revoke_peer(&peer.fingerprint, 2_000)
            .expect("peer revoked");
        assert!(matches!(
            store.trusted_session_peer(&peer.locator, &peer.fingerprint),
            Err(AgentError::SessionAuthorizationDenied)
        ));
        fs::remove_dir_all(state_dir).expect("temporary state cleaned");
    }

    #[test]
    fn unattended_scopes_leases_and_disable_fail_closed_across_restart() {
        let state_dir = temporary_state_dir();
        let peer = peer();
        {
            let mut store = AgentStore::open(&state_dir).expect("store opens");
            store
                .persist_trusted_peer(&peer, 1_000)
                .expect("peer persists");
            store
                .replace_grants(
                    &peer.fingerprint,
                    &[Grant {
                        fingerprint: peer.fingerprint.clone(),
                        revoked: false,
                        not_before: 1_000,
                        expires_at: 20_000,
                        capabilities: vec![Capability::Ssh],
                    }],
                )
                .expect("grant persists");
            assert!(!store.unattended_status().expect("status").enabled);
            store
                .enable_unattended(&[Capability::Ssh], 1_000)
                .expect("explicit local enable");
        }
        {
            let store = AgentStore::open(&state_dir)
                .expect("store reopens")
                .enforce_unattended();
            assert!(store
                .authorize_desktop_session(&peer.locator, &peer.fingerprint, Capability::Ssh, 2_000)
                .is_ok());
            assert!(matches!(
                store.authorize_desktop_session(
                    &peer.locator,
                    &peer.fingerprint,
                    Capability::FilesRead,
                    2_000
                ),
                Err(AgentError::UnattendedAccessDisabled)
            ));
            store
                .record_unattended_session(
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    &peer.fingerprint,
                    "ssh",
                    2_000,
                    3_000,
                )
                .expect("bounded lease");
            assert!(store
                .unattended_session_lease_current(
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    &peer.fingerprint,
                    2_500
                )
                .is_ok());
            assert!(matches!(
                store.unattended_session_lease_current(
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    &peer.fingerprint,
                    3_000
                ),
                Err(AgentError::SessionAuthorizationDenied)
            ));
        }
        {
            let mut store = AgentStore::open(&state_dir).expect("store reopens");
            store
                .disable_unattended(4_000, "local_owner_disabled")
                .expect("disable persists");
            let store = store.enforce_unattended();
            assert!(matches!(
                store.authorize_desktop_session(
                    &peer.locator,
                    &peer.fingerprint,
                    Capability::Ssh,
                    4_000
                ),
                Err(AgentError::UnattendedAccessDisabled)
            ));
            assert!(store
                .security_events(10)
                .expect("events")
                .iter()
                .any(|event| event.event_type == "unattended_disabled"));
        }
        fs::remove_dir_all(state_dir).expect("temporary state cleaned");
    }
}
