//! Attended native pairing over the authenticated coordinator relay.
//!
//! The coordinator only forwards opaque Noise frames.  A local operator must
//! compare and type the transcript-derived SAS before either peer persists a
//! trust record or creates an authorization grant.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use crate::coordinator::AuthenticatedCoordinator;
use crate::identity::{
    bundle_matches_noise_static, pairing_sas, trust_attestation_payload, DeviceIdentity,
    IdentityBundle,
};
use crate::store::{AgentStore, TrustedPeer};
use crate::{AgentError, Result};

const PAIRING_TIMEOUT_MS: u64 = 90_000;
const MAX_NOISE_FRAME_BYTES: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    Host,
    Controller,
}

pub struct PairingResult {
    pub peer: TrustedPeer,
    pub sas: String,
}

fn now_millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::PairingDenied)
        .and_then(|value| u64::try_from(value.as_millis()).map_err(|_| AgentError::PairingDenied))
}

fn object<'a>(value: &'a Value) -> Result<&'a serde_json::Map<String, Value>> {
    value.as_object().ok_or(AgentError::CoordinatorProtocol(
        "malformed pairing event".into(),
    ))
}

fn string<'a>(value: &'a Value, key: &str, min: usize, max: usize) -> Result<&'a str> {
    let result = object(value)?
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| (min..=max).contains(&value.len()))
        .ok_or_else(|| AgentError::CoordinatorProtocol("malformed pairing event".into()))?;
    Ok(result)
}

fn number(value: &Value, key: &str) -> Result<u64> {
    object(value)?
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AgentError::CoordinatorProtocol("malformed pairing event".into()))
}

fn identity_from_event(value: &Value, key: &str) -> Result<IdentityBundle> {
    let peer = object(value)?
        .get(key)
        .ok_or_else(|| AgentError::CoordinatorProtocol("missing pairing peer".into()))?;
    let peer = peer
        .as_object()
        .ok_or_else(|| AgentError::CoordinatorProtocol("malformed pairing peer".into()))?;
    let bundle: IdentityBundle = serde_json::from_value(
        peer.get("bundle")
            .cloned()
            .ok_or_else(|| AgentError::CoordinatorProtocol("missing pairing bundle".into()))?,
    )
    .map_err(|_| AgentError::CoordinatorProtocol("malformed pairing bundle".into()))?;
    let public = bundle.verify()?;
    if peer.get("locator").and_then(Value::as_str) != Some(public.locator.as_str())
        || peer.get("fingerprint").and_then(Value::as_str) != Some(public.fingerprint.as_str())
    {
        return Err(AgentError::PairingDenied);
    }
    Ok(bundle)
}

async fn wait_for(client: &mut AuthenticatedCoordinator, kind: &str) -> Result<Value> {
    loop {
        let value = client.receive_message(PAIRING_TIMEOUT_MS).await?;
        if object(&value)?.get("type").and_then(Value::as_str) == Some(kind) {
            return Ok(value);
        }
    }
}

async fn send_frame(
    client: &mut AuthenticatedCoordinator,
    pairing_id: &str,
    sequence: u32,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_NOISE_FRAME_BYTES {
        return Err(AgentError::PairingDenied);
    }
    client
        .send_message(json!({
            "type": "PAIR_FRAME",
            "pairingId": pairing_id,
            "sequence": sequence,
            "frame": URL_SAFE_NO_PAD.encode(bytes)
        }))
        .await
}

async fn receive_frame(
    client: &mut AuthenticatedCoordinator,
    pairing_id: &str,
    sequence: u32,
    expected: &IdentityBundle,
) -> Result<Vec<u8>> {
    let event = wait_for(client, "PAIR_FRAME").await?;
    if string(&event, "pairingId", 16, 128)? != pairing_id
        || number(&event, "sequence")? != u64::from(sequence)
    {
        return Err(AgentError::PairingDenied);
    }
    let source = object(&event)?
        .get("source")
        .and_then(Value::as_object)
        .ok_or(AgentError::PairingDenied)?;
    let expected_public = expected.verify()?;
    if source.get("locator").and_then(Value::as_str) != Some(expected_public.locator.as_str())
        || source.get("fingerprint").and_then(Value::as_str)
            != Some(expected_public.fingerprint.as_str())
    {
        return Err(AgentError::PairingDenied);
    }
    let raw = string(&event, "frame", 1, 11_000)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AgentError::PairingDenied)?;
    if bytes.is_empty()
        || bytes.len() > MAX_NOISE_FRAME_BYTES
        || URL_SAFE_NO_PAD.encode(&bytes) != raw
    {
        return Err(AgentError::PairingDenied);
    }
    Ok(bytes)
}

fn confirm_sas(sas: &str) -> Result<()> {
    use std::io::{self, Write};
    println!("Pairing SAS: {sas}");
    print!("Compare this value on the other device, then type it exactly to confirm: ");
    io::stdout()
        .flush()
        .map_err(|_| AgentError::PairingDenied)?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| AgentError::PairingDenied)?;
    // Keep subsequent machine-readable diagnostics on their own line.
    println!();
    if input.trim() == sas {
        Ok(())
    } else {
        Err(AgentError::PairingDenied)
    }
}

fn embedded_bundle(payload: &[u8], expected: &IdentityBundle) -> Result<()> {
    let bundle: IdentityBundle =
        serde_json::from_slice(payload).map_err(|_| AgentError::PairingDenied)?;
    if &bundle != expected || bundle.verify()?.fingerprint != expected.verify()?.fingerprint {
        return Err(AgentError::PairingDenied);
    }
    Ok(())
}

async fn finish_trust(
    client: &mut AuthenticatedCoordinator,
    store: &mut AgentStore,
    identity: &DeviceIdentity,
    pairing_id: &str,
    expires_at: u64,
    peer_bundle: &IdentityBundle,
    display_name: String,
    sas: String,
) -> Result<PairingResult> {
    confirm_sas(&sas)?;
    let peer = TrustedPeer::from_verified_bundle(peer_bundle, display_name)?;
    let attestation = trust_attestation_payload(
        pairing_id,
        &identity.public.locator,
        &identity.public.fingerprint,
        &peer.locator,
        &peer.fingerprint,
        expires_at,
    )?;
    client
        .send_message(json!({
            "type": "TRUST_ATTEST",
            "pairingId": pairing_id,
            "expiresAt": expires_at,
            "signature": URL_SAFE_NO_PAD.encode(identity.sign(&attestation))
        }))
        .await?;
    // The first attestation is merely recorded; trust is persisted only after
    // the coordinator confirms both signed attestations are active.
    let active = wait_for(client, "TRUST_LINK_ACTIVE").await?;
    let active_peer = object(&active)?
        .get("peer")
        .and_then(Value::as_object)
        .ok_or(AgentError::PairingDenied)?;
    if active_peer.get("locator").and_then(Value::as_str) != Some(peer.locator.as_str())
        || active_peer.get("fingerprint").and_then(Value::as_str) != Some(peer.fingerprint.as_str())
    {
        return Err(AgentError::PairingDenied);
    }
    store.persist_trusted_peer(&peer, now_millis()?)?;
    Ok(PairingResult { peer, sas })
}

pub async fn host_pair(
    store: &mut AgentStore,
    identity: &DeviceIdentity,
    coordinator_url: &str,
    display_name: String,
) -> Result<PairingResult> {
    let mut client = AuthenticatedCoordinator::connect(coordinator_url, identity).await?;
    client
        .send_message(json!({ "type": "PAIR_INVITE_CREATE", "ttlMs": 300_000 }))
        .await?;
    let invitation = wait_for(&mut client, "PAIR_INVITE").await?;
    println!(
        "Pairing invitation token (share once over a trusted channel): {}",
        string(&invitation, "token", 43, 43)?
    );
    let request = wait_for(&mut client, "PAIR_REQUEST").await?;
    let pairing_id = string(&request, "pairingId", 16, 128)?.to_owned();
    let expires_at = number(&request, "expiresAt")?;
    let peer_bundle = identity_from_event(&request, "controller")?;
    client
        .send_message(json!({ "type": "PAIR_APPROVE", "pairingId": pairing_id }))
        .await?;

    let first = receive_frame(&mut client, &pairing_id, 0, &peer_bundle).await?;
    let mut noise = identity.noise_responder()?;
    let mut plaintext = vec![0_u8; MAX_NOISE_FRAME_BYTES];
    let length = noise
        .read_message(&first, &mut plaintext)
        .map_err(|_| AgentError::PairingDenied)?;
    embedded_bundle(&plaintext[..length], &peer_bundle)?;
    let own_bundle =
        serde_json::to_vec(&identity.identity_bundle()?).map_err(|_| AgentError::PairingDenied)?;
    let mut frame = vec![0_u8; MAX_NOISE_FRAME_BYTES];
    let length = noise
        .write_message(&own_bundle, &mut frame)
        .map_err(|_| AgentError::PairingDenied)?;
    send_frame(&mut client, &pairing_id, 1, &frame[..length]).await?;
    let third = receive_frame(&mut client, &pairing_id, 2, &peer_bundle).await?;
    noise
        .read_message(&third, &mut plaintext)
        .map_err(|_| AgentError::PairingDenied)?;
    if !noise.is_handshake_finished() {
        return Err(AgentError::PairingDenied);
    }
    bundle_matches_noise_static(
        &peer_bundle,
        noise.get_remote_static().ok_or(AgentError::PairingDenied)?,
    )?;
    let sas = pairing_sas(noise.get_handshake_hash())?;
    finish_trust(
        &mut client,
        store,
        identity,
        &pairing_id,
        expires_at,
        &peer_bundle,
        display_name,
        sas,
    )
    .await
}

pub async fn controller_pair(
    store: &mut AgentStore,
    identity: &DeviceIdentity,
    coordinator_url: &str,
    invitation_token: &str,
    display_name: String,
) -> Result<PairingResult> {
    let mut client = AuthenticatedCoordinator::connect(coordinator_url, identity).await?;
    if invitation_token.len() != 43
        || URL_SAFE_NO_PAD
            .decode(invitation_token)
            .map_or(true, |value| value.len() != 32)
    {
        return Err(AgentError::PairingDenied);
    }
    client
        .send_message(json!({ "type": "PAIR_REQUEST", "token": invitation_token, "bundle": identity.identity_bundle()? }))
        .await?;
    let approved = wait_for(&mut client, "PAIR_APPROVED").await?;
    let pairing_id = string(&approved, "pairingId", 16, 128)?.to_owned();
    let expires_at = number(&approved, "expiresAt")?;
    let peer_bundle = identity_from_event(&approved, "host")?;
    let mut noise = identity.noise_initiator()?;
    let own_bundle =
        serde_json::to_vec(&identity.identity_bundle()?).map_err(|_| AgentError::PairingDenied)?;
    let mut frame = vec![0_u8; MAX_NOISE_FRAME_BYTES];
    let length = noise
        .write_message(&own_bundle, &mut frame)
        .map_err(|_| AgentError::PairingDenied)?;
    send_frame(&mut client, &pairing_id, 0, &frame[..length]).await?;
    let second = receive_frame(&mut client, &pairing_id, 1, &peer_bundle).await?;
    let mut plaintext = vec![0_u8; MAX_NOISE_FRAME_BYTES];
    let length = noise
        .read_message(&second, &mut plaintext)
        .map_err(|_| AgentError::PairingDenied)?;
    embedded_bundle(&plaintext[..length], &peer_bundle)?;
    let length = noise
        .write_message(&[], &mut frame)
        .map_err(|_| AgentError::PairingDenied)?;
    send_frame(&mut client, &pairing_id, 2, &frame[..length]).await?;
    if !noise.is_handshake_finished() {
        return Err(AgentError::PairingDenied);
    }
    bundle_matches_noise_static(
        &peer_bundle,
        noise.get_remote_static().ok_or(AgentError::PairingDenied)?,
    )?;
    let sas = pairing_sas(noise.get_handshake_hash())?;
    finish_trust(
        &mut client,
        store,
        identity,
        &pairing_id,
        expires_at,
        &peer_bundle,
        display_name,
        sas,
    )
    .await
}
