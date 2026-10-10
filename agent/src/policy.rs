use serde::Deserialize;

pub const CAPABILITIES: [&str; 5] = [
    "desktop.view",
    "desktop.control",
    "ssh",
    "files.read",
    "files.write",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum Capability {
    #[serde(rename = "desktop.view")]
    DesktopView,
    #[serde(rename = "desktop.control")]
    DesktopControl,
    #[serde(rename = "ssh")]
    Ssh,
    #[serde(rename = "files.read")]
    FilesRead,
    #[serde(rename = "files.write")]
    FilesWrite,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesktopView => "desktop.view",
            Self::DesktopControl => "desktop.control",
            Self::Ssh => "ssh",
            Self::FilesRead => "files.read",
            Self::FilesWrite => "files.write",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Grant {
    pub fingerprint: String,
    pub revoked: bool,
    #[serde(rename = "notBefore")]
    pub not_before: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub enabled: bool,
    pub grants: Vec<Grant>,
}

/// This type is only constructed after signature verification and pinned-key
/// comparison in the native agent. It intentionally has no client supplied
/// `authenticated` boolean.
#[derive(Debug)]
pub struct AuthenticatedPeer {
    pub fingerprint: String,
}

#[derive(Debug, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: &'static str,
}

fn fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn authorize_unattended(
    policy: Option<&Policy>,
    peer: Option<&AuthenticatedPeer>,
    capability: Option<Capability>,
    now: u64,
) -> Decision {
    let Some(policy) = policy else {
        return Decision {
            allowed: false,
            reason: "unattended_disabled",
        };
    };
    if !policy.enabled {
        return Decision {
            allowed: false,
            reason: "unattended_disabled",
        };
    }
    let Some(peer) = peer else {
        return Decision {
            allowed: false,
            reason: "peer_not_authenticated",
        };
    };
    if !fingerprint(&peer.fingerprint) {
        return Decision {
            allowed: false,
            reason: "peer_not_authenticated",
        };
    }
    let Some(capability) = capability else {
        return Decision {
            allowed: false,
            reason: "unknown_capability",
        };
    };
    let grants: Vec<&Grant> = policy
        .grants
        .iter()
        .filter(|grant| grant.fingerprint == peer.fingerprint)
        .collect();
    if grants.len() != 1 {
        return Decision {
            allowed: false,
            reason: "missing_or_ambiguous_grant",
        };
    }
    let grant = grants[0];
    if grant.revoked {
        return Decision {
            allowed: false,
            reason: "grant_revoked_or_invalid",
        };
    }
    if grant.not_before > grant.expires_at || now < grant.not_before || now >= grant.expires_at {
        return Decision {
            allowed: false,
            reason: "grant_not_current",
        };
    }
    if !grant.capabilities.contains(&capability) {
        return Decision {
            allowed: false,
            reason: "capability_denied",
        };
    }
    Decision {
        allowed: true,
        reason: "trusted_device_grant",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct VectorPeer {
        authenticated: bool,
        fingerprint: String,
    }

    #[derive(Deserialize)]
    struct VectorInput {
        #[serde(default)]
        policy: Option<Policy>,
        #[serde(default)]
        peer: Option<VectorPeer>,
        #[serde(default)]
        capability: Option<Capability>,
        #[serde(default)]
        now: Option<u64>,
    }

    #[derive(Deserialize)]
    struct VectorExpected {
        allowed: bool,
        reason: String,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        input: VectorInput,
        expected: VectorExpected,
    }

    #[test]
    fn shared_conformance_vectors_match_the_javascript_policy() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../packages/policy/conformance-vectors.json"
        ))
        .expect("conformance vectors are valid JSON");
        for vector in vectors {
            let authenticated_peer = vector.input.peer.as_ref().and_then(|peer| {
                peer.authenticated.then(|| AuthenticatedPeer {
                    fingerprint: peer.fingerprint.clone(),
                })
            });
            let decision = authorize_unattended(
                vector.input.policy.as_ref(),
                authenticated_peer.as_ref(),
                vector.input.capability,
                vector.input.now.unwrap_or(0),
            );
            assert_eq!(
                decision.allowed, vector.expected.allowed,
                "{} allowed",
                vector.name
            );
            assert_eq!(
                decision.reason, vector.expected.reason,
                "{} reason",
                vector.name
            );
        }
    }
}
