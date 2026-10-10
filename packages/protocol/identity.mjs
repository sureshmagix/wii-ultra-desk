import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify
} from 'node:crypto';

export const IDENTITY_VERSION = 1;
export const DEVICE_LOCATOR_BYTES = 16;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const X25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

const IDENTITY_DOMAIN = Buffer.from('WII-ULTRA-DESK/IDENTITY-BUNDLE/V1\0', 'utf8');
const AUTH_DOMAIN = Buffer.from('WII-ULTRA-DESK/COORDINATOR-AUTH/V1\0', 'utf8');
const TRUST_DOMAIN = Buffer.from('WII-ULTRA-DESK/TRUST-ATTESTATION/V1\0', 'utf8');
const FINGERPRINT_DOMAIN = Buffer.from('WII-ULTRA-DESK/ED25519-FINGERPRINT/V1\0', 'utf8');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export class ProtocolError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

function requirePlainObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ProtocolError(code);
  }
}

function requireExactKeys(value, keys, code) {
  requirePlainObject(value, code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ProtocolError(code);
  }
}

function encodeField(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  if (bytes.length > 0xffff_ffff) throw new ProtocolError('field_too_large');
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function encodeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('invalid_integer');
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function decodeBase64Url(value, length, code) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) throw new ProtocolError(code);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) throw new ProtocolError(code);
  return bytes;
}

export function createLocator() {
  return randomBytes(DEVICE_LOCATOR_BYTES).toString('base64url');
}

export function validateLocator(locator) {
  if (typeof locator !== 'string' || locator.length !== 22 || !BASE64URL.test(locator)) {
    throw new ProtocolError('invalid_locator');
  }
  const bytes = Buffer.from(locator, 'base64url');
  if (bytes.length !== DEVICE_LOCATOR_BYTES || bytes.toString('base64url') !== locator) {
    throw new ProtocolError('invalid_locator');
  }
  return locator;
}

export function fingerprintFromSigningPublicKey(signingPublicKey) {
  const raw = Buffer.isBuffer(signingPublicKey)
    ? signingPublicKey
    : decodeBase64Url(signingPublicKey, ED25519_PUBLIC_KEY_BYTES, 'invalid_signing_public_key');
  if (raw.length !== ED25519_PUBLIC_KEY_BYTES) throw new ProtocolError('invalid_signing_public_key');
  return createHash('sha256').update(FINGERPRINT_DOMAIN).update(raw).digest('hex');
}

export function identityBundlePayload({ version, locator, signingPublicKey, noisePublicKey, createdAt }) {
  if (version !== IDENTITY_VERSION) throw new ProtocolError('unsupported_identity_version');
  validateLocator(locator);
  const signingKey = decodeBase64Url(signingPublicKey, ED25519_PUBLIC_KEY_BYTES, 'invalid_signing_public_key');
  const noiseKey = decodeBase64Url(noisePublicKey, X25519_PUBLIC_KEY_BYTES, 'invalid_noise_public_key');
  return Buffer.concat([
    IDENTITY_DOMAIN,
    Buffer.from([version]),
    encodeField(locator),
    encodeField(signingKey),
    encodeField(noiseKey),
    encodeInteger(createdAt)
  ]);
}

export function publicKeyFromRawEd25519(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new ProtocolError('invalid_signing_public_key');
  }
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki'
  });
  if (key.asymmetricKeyType !== 'ed25519') throw new ProtocolError('invalid_signing_public_key');
  return key;
}

export function verifyIdentityBundle(value) {
  requireExactKeys(value, ['createdAt', 'locator', 'noisePublicKey', 'signature', 'signingPublicKey', 'version'], 'invalid_identity_bundle');
  const payload = identityBundlePayload(value);
  const signingKey = decodeBase64Url(value.signingPublicKey, ED25519_PUBLIC_KEY_BYTES, 'invalid_signing_public_key');
  const signature = decodeBase64Url(value.signature, ED25519_SIGNATURE_BYTES, 'invalid_identity_signature');
  const publicKey = publicKeyFromRawEd25519(signingKey);
  if (!verify(null, payload, publicKey, signature)) throw new ProtocolError('invalid_identity_signature');
  return Object.freeze({
    bundle: Object.freeze({
      version: value.version,
      locator: value.locator,
      signingPublicKey: value.signingPublicKey,
      noisePublicKey: value.noisePublicKey,
      createdAt: value.createdAt,
      signature: value.signature
    }),
    fingerprint: fingerprintFromSigningPublicKey(signingKey),
    signingPublicKey: signingKey,
    publicKey
  });
}

export function authProofPayload({ connectionId, nonce, locator, fingerprint, expiresAt }) {
  if (typeof connectionId !== 'string' || connectionId.length < 16 || connectionId.length > 128) {
    throw new ProtocolError('invalid_connection_id');
  }
  const nonceBytes = decodeBase64Url(nonce, 32, 'invalid_nonce');
  validateLocator(locator);
  if (typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(fingerprint)) {
    throw new ProtocolError('invalid_fingerprint');
  }
  return Buffer.concat([
    AUTH_DOMAIN,
    encodeField(connectionId),
    encodeField(nonceBytes),
    encodeField(locator),
    encodeField(fingerprint),
    encodeInteger(expiresAt)
  ]);
}

export function trustAttestationPayload({ pairingId, sourceLocator, sourceFingerprint, peerLocator, peerFingerprint, expiresAt }) {
  if (typeof pairingId !== 'string' || pairingId.length < 16 || pairingId.length > 128) {
    throw new ProtocolError('invalid_pairing_id');
  }
  validateLocator(sourceLocator);
  validateLocator(peerLocator);
  for (const value of [sourceFingerprint, peerFingerprint]) {
    if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new ProtocolError('invalid_fingerprint');
  }
  return Buffer.concat([
    TRUST_DOMAIN,
    encodeField(pairingId),
    encodeField(sourceLocator),
    encodeField(sourceFingerprint),
    encodeField(peerLocator),
    encodeField(peerFingerprint),
    encodeInteger(expiresAt)
  ]);
}

export function createDevelopmentIdentity({ locator = createLocator(), createdAt = Date.now() } = {}) {
  validateLocator(locator);
  const keys = generateKeyPairSync('ed25519');
  const noiseKeys = generateKeyPairSync('x25519');
  const publicDer = keys.publicKey.export({ format: 'der', type: 'spki' });
  const noisePublicDer = noiseKeys.publicKey.export({ format: 'der', type: 'spki' });
  const signingPublicKey = publicDer.subarray(-ED25519_PUBLIC_KEY_BYTES).toString('base64url');
  const noisePublicKey = noisePublicDer.subarray(-X25519_PUBLIC_KEY_BYTES).toString('base64url');
  const unsignedBundle = {
    version: IDENTITY_VERSION,
    locator,
    signingPublicKey,
    noisePublicKey,
    createdAt
  };
  const signature = sign(null, identityBundlePayload(unsignedBundle), keys.privateKey).toString('base64url');
  const bundle = Object.freeze({ ...unsignedBundle, signature });
  const verified = verifyIdentityBundle(bundle);
  return Object.freeze({
    privateKey: keys.privateKey,
    bundle,
    fingerprint: verified.fingerprint
  });
}

export function signAuthProof(identity, challenge) {
  return sign(null, authProofPayload(challenge), identity.privateKey).toString('base64url');
}

export function signTrustAttestation(identity, attestation) {
  return sign(null, trustAttestationPayload(attestation), identity.privateKey).toString('base64url');
}

export function verifyTrustAttestation(signature, signingPublicKey, attestation) {
  const signatureBytes = decodeBase64Url(signature, ED25519_SIGNATURE_BYTES, 'invalid_trust_attestation_signature');
  const rawKey = Buffer.isBuffer(signingPublicKey)
    ? signingPublicKey
    : decodeBase64Url(signingPublicKey, ED25519_PUBLIC_KEY_BYTES, 'invalid_signing_public_key');
  return verify(null, trustAttestationPayload(attestation), publicKeyFromRawEd25519(rawKey), signatureBytes);
}

export function randomInvitationToken() {
  return randomBytes(32).toString('base64url');
}

export function invitationTokenHash(token) {
  const bytes = decodeBase64Url(token, 32, 'invalid_invitation_token');
  return createHash('sha256').update('WII-ULTRA-DESK/PAIRING-INVITATION/V1\0').update(bytes).digest('hex');
}

export function decodeOpaqueFrame(value, maxBytes = 8192) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) throw new ProtocolError('invalid_opaque_frame');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== value) {
    throw new ProtocolError('invalid_opaque_frame');
  }
  return bytes;
}
