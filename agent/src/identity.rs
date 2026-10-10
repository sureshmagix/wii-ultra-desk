use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder, HandshakeState};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{AgentError, Result};

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const FINGERPRINT_DOMAIN: &[u8] = b"WII-ULTRA-DESK/ED25519-FINGERPRINT/V1\0";
const IDENTITY_DOMAIN: &[u8] = b"WII-ULTRA-DESK/IDENTITY-BUNDLE/V1\0";
const AUTH_DOMAIN: &[u8] = b"WII-ULTRA-DESK/COORDINATOR-AUTH/V1\0";
const TRUST_DOMAIN: &[u8] = b"WII-ULTRA-DESK/TRUST-ATTESTATION/V1\0";
const SAS_DOMAIN: &[u8] = b"WII-ULTRA-DESK/PAIRING-SAS/V1\0";

pub const IDENTITY_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct DeviceIdentityPublic {
    pub locator: String,
    pub fingerprint: String,
    pub signing_public_key: String,
    pub noise_public_key: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBundle {
    pub version: u8,
    pub locator: String,
    pub signing_public_key: String,
    pub noise_public_key: String,
    pub created_at: u64,
    pub signature: String,
}

/// Private fields are deliberately not serializable or exposed through local IPC.
pub struct DeviceIdentity {
    pub public: DeviceIdentityPublic,
    signing_key: SigningKey,
    noise_static_private: Vec<u8>,
}

fn locator() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn encode_field(value: &[u8], output: &mut Vec<u8>) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| AgentError::InvalidIdentityMaterial)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn encode_integer(value: u64, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    bytes
        .try_into()
        .map_err(|_| AgentError::InvalidIdentityMaterial)
}

fn decode_exact(value: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    if bytes.len() != length || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    Ok(bytes)
}

pub fn validate_locator(value: &str) -> Result<()> {
    if value.len() != 22 {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    decode_exact(value, 16).map(|_| ())
}

pub fn identity_bundle_payload(
    version: u8,
    locator: &str,
    signing_public_key: &str,
    noise_public_key: &str,
    created_at: u64,
) -> Result<Vec<u8>> {
    if version != IDENTITY_VERSION {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    validate_locator(locator)?;
    let signing_public_key = decode_key(signing_public_key)?;
    let noise_public_key = decode_key(noise_public_key)?;
    let mut output = Vec::with_capacity(IDENTITY_DOMAIN.len() + 160);
    output.extend_from_slice(IDENTITY_DOMAIN);
    output.push(version);
    encode_field(locator.as_bytes(), &mut output)?;
    encode_field(&signing_public_key, &mut output)?;
    encode_field(&noise_public_key, &mut output)?;
    encode_integer(created_at, &mut output);
    Ok(output)
}

pub fn trust_attestation_payload(
    pairing_id: &str,
    source_locator: &str,
    source_fingerprint: &str,
    peer_locator: &str,
    peer_fingerprint: &str,
    expires_at: u64,
) -> Result<Vec<u8>> {
    if !(16..=128).contains(&pairing_id.len())
        || !valid_fingerprint(source_fingerprint)
        || !valid_fingerprint(peer_fingerprint)
    {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    validate_locator(source_locator)?;
    validate_locator(peer_locator)?;
    let mut output = Vec::with_capacity(TRUST_DOMAIN.len() + 512);
    output.extend_from_slice(TRUST_DOMAIN);
    for field in [
        pairing_id.as_bytes(),
        source_locator.as_bytes(),
        source_fingerprint.as_bytes(),
        peer_locator.as_bytes(),
        peer_fingerprint.as_bytes(),
    ] {
        encode_field(field, &mut output)?;
    }
    encode_integer(expires_at, &mut output);
    Ok(output)
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Six decimal groups derived from the Noise transcript.  This is deliberately
/// for a human out-of-band comparison, never an authentication substitute.
pub fn pairing_sas(handshake_hash: &[u8]) -> Result<String> {
    if handshake_hash.len() != 32 {
        return Err(AgentError::PairingDenied);
    }
    let digest = Sha256::new()
        .chain_update(SAS_DOMAIN)
        .chain_update(handshake_hash)
        .finalize();
    Ok((0..6)
        .map(|index| {
            let offset = index * 4;
            let value = u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("slice"));
            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join("-"))
}

pub fn auth_proof_payload(
    connection_id: &str,
    nonce: &str,
    locator: &str,
    fingerprint: &str,
    expires_at: u64,
) -> Result<Vec<u8>> {
    if !(16..=128).contains(&connection_id.len()) || locator.len() != 22 || fingerprint.len() != 64
    {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    if nonce.len() != 32 {
        return Err(AgentError::InvalidIdentityMaterial);
    }
    let mut output = Vec::with_capacity(AUTH_DOMAIN.len() + 256);
    output.extend_from_slice(AUTH_DOMAIN);
    encode_field(connection_id.as_bytes(), &mut output)?;
    encode_field(&nonce, &mut output)?;
    encode_field(locator.as_bytes(), &mut output)?;
    encode_field(fingerprint.as_bytes(), &mut output)?;
    encode_integer(expires_at, &mut output);
    Ok(output)
}

pub fn fingerprint(signing_public_key: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_DOMAIN)
        .chain_update(signing_public_key)
        .finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn noise_keypair() -> Result<snow::Keypair> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    Ok(Builder::new(params).generate_keypair()?)
}

impl DeviceIdentity {
    pub fn generate(created_at: u64) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let noise_keypair = noise_keypair()?;
        Self::from_stored_secrets(
            locator(),
            signing_key.to_bytes().to_vec(),
            noise_keypair.private,
            URL_SAFE_NO_PAD.encode(noise_keypair.public),
            created_at,
        )
    }

    pub fn from_stored_secrets(
        locator: String,
        signing_secret: Vec<u8>,
        noise_static_private: Vec<u8>,
        noise_public_key: String,
        created_at: u64,
    ) -> Result<Self> {
        if locator.len() != 22 || signing_secret.len() != 32 || noise_static_private.len() != 32 {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let decoded_noise_public_key = URL_SAFE_NO_PAD
            .decode(&noise_public_key)
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        if decoded_noise_public_key.len() != 32 {
            return Err(AgentError::InvalidIdentityMaterial);
        }
        let noise_private: [u8; 32] = noise_static_private
            .as_slice()
            .try_into()
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        let derived_noise_public_key = X25519PublicKey::from(&StaticSecret::from(noise_private));
        if decoded_noise_public_key.as_slice() != derived_noise_public_key.as_bytes() {
            return Err(AgentError::IdentityInconsistent);
        }
        let signing_secret: [u8; 32] = signing_secret
            .try_into()
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        let signing_key = SigningKey::from_bytes(&signing_secret);
        let signing_public_key = signing_key.verifying_key().to_bytes();
        Ok(Self {
            public: DeviceIdentityPublic {
                locator,
                fingerprint: fingerprint(&signing_public_key),
                signing_public_key: URL_SAFE_NO_PAD.encode(signing_public_key),
                noise_public_key,
                created_at,
            },
            signing_key,
            noise_static_private,
        })
    }

    pub fn signing_secret(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    pub fn noise_static_secret(&self) -> Vec<u8> {
        self.noise_static_private.clone()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn identity_bundle(&self) -> Result<IdentityBundle> {
        let payload = identity_bundle_payload(
            IDENTITY_VERSION,
            &self.public.locator,
            &self.public.signing_public_key,
            &self.public.noise_public_key,
            self.public.created_at,
        )?;
        Ok(IdentityBundle {
            version: IDENTITY_VERSION,
            locator: self.public.locator.clone(),
            signing_public_key: self.public.signing_public_key.clone(),
            noise_public_key: self.public.noise_public_key.clone(),
            created_at: self.public.created_at,
            signature: URL_SAFE_NO_PAD.encode(self.sign(&payload)),
        })
    }

    pub fn noise_initiator(&self) -> Result<HandshakeState> {
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        Ok(Builder::new(params)
            .local_private_key(&self.noise_static_private)?
            .build_initiator()?)
    }

    pub fn noise_responder(&self) -> Result<HandshakeState> {
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        Ok(Builder::new(params)
            .local_private_key(&self.noise_static_private)?
            .build_responder()?)
    }
}

impl IdentityBundle {
    /// Verify a self-signed bundle before it can become a local trust record.
    /// The Noise static key is checked separately against the Noise handshake.
    pub fn verify(&self) -> Result<DeviceIdentityPublic> {
        let payload = identity_bundle_payload(
            self.version,
            &self.locator,
            &self.signing_public_key,
            &self.noise_public_key,
            self.created_at,
        )?;
        let signature = decode_exact(&self.signature, 64)?;
        let signing_key = decode_key(&self.signing_public_key)?;
        let verifying_key = VerifyingKey::from_bytes(&signing_key)
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| AgentError::InvalidIdentityMaterial)?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| AgentError::InvalidIdentityMaterial)?;
        Ok(DeviceIdentityPublic {
            locator: self.locator.clone(),
            fingerprint: fingerprint(&signing_key),
            signing_public_key: self.signing_public_key.clone(),
            noise_public_key: self.noise_public_key.clone(),
            created_at: self.created_at,
        })
    }
}

pub fn bundle_matches_noise_static(bundle: &IdentityBundle, remote_static: &[u8]) -> Result<()> {
    let expected = decode_key(&bundle.noise_public_key)?;
    if remote_static != expected {
        return Err(AgentError::PairingDenied);
    }
    Ok(())
}

pub fn verify_signature(signing_public_key: &str, payload: &[u8], signature: &str) -> Result<bool> {
    let verifying_key = VerifyingKey::from_bytes(&decode_key(signing_public_key)?)
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AgentError::InvalidIdentityMaterial)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| AgentError::InvalidIdentityMaterial)?;
    Ok(verifying_key.verify(payload, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_xx_completes_with_independent_static_keys() {
        let initiator_identity = DeviceIdentity::generate(1).expect("initiator identity");
        let responder_identity = DeviceIdentity::generate(2).expect("responder identity");
        let mut initiator = initiator_identity
            .noise_initiator()
            .expect("initiator handshake");
        let mut responder = responder_identity
            .noise_responder()
            .expect("responder handshake");
        let mut frame = [0u8; 65_535];
        let mut payload = [0u8; 65_535];

        let first = initiator
            .write_message(&[], &mut frame)
            .expect("first Noise message");
        responder
            .read_message(&frame[..first], &mut payload)
            .expect("read first Noise message");
        let second = responder
            .write_message(&[], &mut frame)
            .expect("second Noise message");
        initiator
            .read_message(&frame[..second], &mut payload)
            .expect("read second Noise message");
        let third = initiator
            .write_message(&[], &mut frame)
            .expect("third Noise message");
        responder
            .read_message(&frame[..third], &mut payload)
            .expect("read third Noise message");

        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());
        assert_eq!(
            initiator.get_handshake_hash(),
            responder.get_handshake_hash()
        );
    }

    #[test]
    fn signed_bundle_and_sas_reject_tampering_and_bind_the_noise_key() {
        let identity = DeviceIdentity::generate(1).expect("identity");
        let bundle = identity.identity_bundle().expect("bundle");
        let verified = bundle.verify().expect("signed bundle verifies");
        assert_eq!(verified.fingerprint, identity.public.fingerprint);
        let noise = URL_SAFE_NO_PAD
            .decode(&bundle.noise_public_key)
            .expect("noise key");
        bundle_matches_noise_static(&bundle, &noise).expect("Noise static key matches bundle");
        let mut tampered = bundle.clone();
        tampered.locator = "AAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(tampered.verify().is_err());
        assert!(pairing_sas(&[0_u8; 31]).is_err());
        assert_ne!(
            pairing_sas(&[1_u8; 32]).unwrap(),
            pairing_sas(&[2_u8; 32]).unwrap()
        );
    }
}
