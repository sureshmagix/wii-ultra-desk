// Reference authorization policy. Inputs MUST come from host-owned storage and
// an authenticated transport, never directly from an incoming client request.
// This does not implement authentication, signature verification or persistence.
export const CAPABILITIES = Object.freeze([
  'desktop.view', 'desktop.control', 'ssh', 'files.read', 'files.write'
]);
const fingerprint = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const deny = reason => ({ allowed: false, reason });

export function authorizeUnattended({ policy, peer, capability, now = Date.now() } = {}) {
  if (!Number.isSafeInteger(now) || now < 0) return deny('invalid_time');
  if (!policy || policy.enabled !== true) return deny('unattended_disabled');
  if (!peer || peer.authenticated !== true || !fingerprint(peer.fingerprint)) {
    return deny('peer_not_authenticated');
  }
  if (!CAPABILITIES.includes(capability)) return deny('unknown_capability');
  if (!Array.isArray(policy.grants)) return deny('invalid_policy');
  // Duplicate identities fail closed rather than selecting a stale grant.
  const matches = policy.grants.filter(g => g && g.fingerprint === peer.fingerprint);
  if (matches.length !== 1) return deny('missing_or_ambiguous_grant');
  const grant = matches[0];
  if (grant.revoked !== false) return deny('grant_revoked_or_invalid');
  if (!Number.isSafeInteger(grant.notBefore) || grant.notBefore < 0 ||
      !Number.isSafeInteger(grant.expiresAt) || grant.expiresAt <= grant.notBefore ||
      now < grant.notBefore || now >= grant.expiresAt) return deny('grant_not_current');
  if (!Array.isArray(grant.capabilities) ||
      grant.capabilities.some(c => !CAPABILITIES.includes(c)) ||
      !grant.capabilities.includes(capability)) return deny('capability_denied');
  return { allowed: true, reason: 'trusted_device_grant' };
}
