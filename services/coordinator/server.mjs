import crypto from 'node:crypto';
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { WebSocket, WebSocketServer } from 'ws';
import {
  ProtocolError,
  authProofPayload,
  decodeOpaqueFrame,
  invitationTokenHash,
  randomInvitationToken,
  validateLocator,
  verifyIdentityBundle,
  verifyTrustAttestation
} from '../../packages/protocol/identity.mjs';

const MAX_HTTP_BODY_BYTES = 16 * 1024;
const MAX_WS_MESSAGE_BYTES = 16 * 1024;
const AUTH_CHALLENGE_TTL_MS = 60_000;
const SESSION_TTL_MS = 15 * 60_000;
const MAX_INVITATION_TTL_MS = 10 * 60_000;
const MAX_TURN_CREDENTIAL_TTL_MS = 10 * 60_000;
const MIN_TURN_CREDENTIAL_TTL_MS = 30_000;
const MAX_CONNECTIONS = 1_024;
const MAX_DEVICE_CONNECTIONS = 2;
const STATUS_CAPABILITY = 'desktop.view';

class CoordinatorError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'CoordinatorError';
    this.code = code;
  }
}

class TokenBucket {
  #entries = new Map();

  consume(key, { capacity, refillPerMinute }, now) {
    const prior = this.#entries.get(key) ?? { tokens: capacity, updatedAt: now };
    const elapsed = Math.max(0, now - prior.updatedAt);
    const tokens = Math.min(capacity, prior.tokens + (elapsed * refillPerMinute) / 60_000);
    if (tokens < 1) {
      this.#entries.set(key, { tokens, updatedAt: now });
      return false;
    }
    this.#entries.set(key, { tokens: tokens - 1, updatedAt: now });
    return true;
  }
}

function requireObject(value, code = 'invalid_message') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new CoordinatorError(code);
  }
}

function requireExactKeys(value, keys, code = 'invalid_message') {
  requireObject(value, code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new CoordinatorError(code);
  }
}

function requireString(value, { min = 1, max = 256, code = 'invalid_message', pattern } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max || (pattern && !pattern.test(value))) {
    throw new CoordinatorError(code);
  }
  return value;
}

function requireSafeInteger(value, { min = 0, max = Number.MAX_SAFE_INTEGER, code = 'invalid_message' } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new CoordinatorError(code);
  return value;
}

function requireFingerprint(value) {
  return requireString(value, { min: 64, max: 64, pattern: /^[a-f0-9]{64}$/, code: 'invalid_fingerprint' });
}

function requireDestination(value) {
  requireExactKeys(value, ['fingerprint', 'locator'], 'invalid_destination');
  try {
    return { locator: validateLocator(value.locator), fingerprint: requireFingerprint(value.fingerprint) };
  } catch (error) {
    if (error instanceof ProtocolError) throw new CoordinatorError(error.code);
    throw error;
  }
}

function requireSignalPayload(value) {
  requireExactKeys(value, ['data', 'kind'], 'invalid_signal_payload');
  const kind = requireString(value.kind, { min: 1, max: 32, pattern: /^(webrtc\.(offer|answer|candidate|cancel)|control\.revocation(-ack)?)$/, code: 'invalid_signal_payload' });
  const data = requireString(value.data, { min: 1, max: 12_000, pattern: /^[A-Za-z0-9_-]+$/, code: 'invalid_signal_payload' });
  const bytes = Buffer.from(data, 'base64url');
  if (bytes.length === 0 || bytes.length > 8_192 || bytes.toString('base64url') !== data) {
    throw new CoordinatorError('invalid_signal_payload');
  }
  return { kind, data };
}

function requireSessionId(value) {
  const sessionId = requireString(value, { min: 22, max: 22, pattern: /^[A-Za-z0-9_-]+$/, code: 'invalid_session_id' });
  const bytes = Buffer.from(sessionId, 'base64url');
  if (bytes.length !== 16 || bytes.toString('base64url') !== sessionId) throw new CoordinatorError('invalid_session_id');
  return sessionId;
}

function normalizeTurnConfiguration(turn) {
  if (!turn) return undefined;
  requireExactKeys(turn, ['sharedSecret', 'urls'], 'invalid_turn_configuration');
  const sharedSecret = requireString(turn.sharedSecret, { min: 32, max: 512, code: 'invalid_turn_configuration' });
  if (!Array.isArray(turn.urls) || turn.urls.length === 0 || turn.urls.length > 4 ||
      turn.urls.some(url => typeof url !== 'string' || url.length > 256 || !/^turns?:/.test(url))) {
    throw new CoordinatorError('invalid_turn_configuration');
  }
  return Object.freeze({ sharedSecret, urls: Object.freeze([...turn.urls]) });
}

function turnCredential(turn, auth, sessionId, expiresAt) {
  // coturn's REST mechanism accepts an expiry-prefixed username and validates
  // base64(HMAC-SHA1(static-auth-secret, username)).  The shared secret stays
  // only in this coordinator process.
  const username = `${Math.floor(expiresAt / 1_000)}:${auth.locator}:${sessionId}`;
  const credential = crypto.createHmac('sha1', turn.sharedSecret).update(username).digest('base64');
  return { urls: turn.urls, username, credential };
}

function remoteAddress(request) {
  return request.socket.remoteAddress ?? 'unknown';
}

function orderedLink(left, right) {
  const items = [left, right].sort((a, b) => a.locator.localeCompare(b.locator));
  return { left: items[0], right: items[1] };
}

class CoordinatorStore {
  constructor(databasePath, now) {
    this.db = new DatabaseSync(databasePath);
    this.now = now;
    this.db.exec('PRAGMA foreign_keys = ON');
    this.migrate();
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS devices (
        locator TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL UNIQUE,
        signing_public_key TEXT NOT NULL,
        noise_public_key TEXT NOT NULL,
        bundle_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        registered_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS invitations (
        token_hash TEXT PRIMARY KEY,
        host_locator TEXT NOT NULL REFERENCES devices(locator),
        host_fingerprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pairings (
        pairing_id TEXT PRIMARY KEY,
        host_locator TEXT NOT NULL,
        host_fingerprint TEXT NOT NULL,
        controller_locator TEXT NOT NULL,
        controller_fingerprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('requested', 'approved', 'trusted', 'rejected', 'expired')),
        host_approved_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS pairing_attestations (
        pairing_id TEXT NOT NULL REFERENCES pairings(pairing_id),
        locator TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        signature TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY(pairing_id, locator)
      );
      CREATE TABLE IF NOT EXISTS trust_links (
        left_locator TEXT NOT NULL,
        left_fingerprint TEXT NOT NULL,
        right_locator TEXT NOT NULL,
        right_fingerprint TEXT NOT NULL,
        pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(pairing_id),
        active INTEGER NOT NULL CHECK(active IN (0, 1)),
        created_at INTEGER NOT NULL,
        revoked_at INTEGER,
        PRIMARY KEY(left_locator, right_locator)
      );
    `);
    const applied = this.db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get(1);
    if (!applied) this.db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(1, this.now());
  }

  transaction(callback) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = callback();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  register(bundle) {
    const now = this.now();
    return this.transaction(() => {
      const existing = this.db.prepare('SELECT * FROM devices WHERE locator = ?').get(bundle.bundle.locator);
      const byFingerprint = this.db.prepare('SELECT locator FROM devices WHERE fingerprint = ?').get(bundle.fingerprint);
      if (existing) {
        if (existing.fingerprint !== bundle.fingerprint ||
            existing.signing_public_key !== bundle.bundle.signingPublicKey ||
            existing.noise_public_key !== bundle.bundle.noisePublicKey) {
          throw new CoordinatorError('identity_mismatch');
        }
        this.db.prepare('UPDATE devices SET last_seen_at = ? WHERE locator = ?').run(now, bundle.bundle.locator);
        return { isNew: false };
      }
      if (byFingerprint) throw new CoordinatorError('fingerprint_already_registered');
      this.db.prepare(`INSERT INTO devices
        (locator, fingerprint, signing_public_key, noise_public_key, bundle_json, created_at, registered_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(bundle.bundle.locator, bundle.fingerprint, bundle.bundle.signingPublicKey,
          bundle.bundle.noisePublicKey, JSON.stringify(bundle.bundle), bundle.bundle.createdAt, now, now);
      return { isNew: true };
    });
  }

  createInvitation(host, ttlMs) {
    const now = this.now();
    const token = randomInvitationToken();
    const expiresAt = now + ttlMs;
    this.db.prepare(`INSERT INTO invitations
      (token_hash, host_locator, host_fingerprint, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)`).run(invitationTokenHash(token), host.locator, host.fingerprint, expiresAt, now);
    return { token, expiresAt };
  }

  reserveInvitation(token, controller) {
    const now = this.now();
    return this.transaction(() => {
      const invitation = this.db.prepare('SELECT * FROM invitations WHERE token_hash = ?').get(invitationTokenHash(token));
      if (!invitation || invitation.consumed_at !== null || now >= invitation.expires_at) {
        throw new CoordinatorError('invitation_invalid_or_expired');
      }
      if (invitation.host_locator === controller.locator) throw new CoordinatorError('self_pairing_denied');
      const pairingId = crypto.randomUUID();
      this.db.prepare('UPDATE invitations SET consumed_at = ? WHERE token_hash = ?').run(now, invitation.token_hash);
      this.db.prepare(`INSERT INTO pairings
        (pairing_id, host_locator, host_fingerprint, controller_locator, controller_fingerprint, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'requested')`)
        .run(pairingId, invitation.host_locator, invitation.host_fingerprint,
          controller.locator, controller.fingerprint, invitation.expires_at);
      return {
        pairingId,
        host: { locator: invitation.host_locator, fingerprint: invitation.host_fingerprint },
        controller: { locator: controller.locator, fingerprint: controller.fingerprint },
        expiresAt: invitation.expires_at
      };
    });
  }

  getPairing(pairingId) {
    const pairing = this.db.prepare('SELECT * FROM pairings WHERE pairing_id = ?').get(pairingId);
    if (!pairing) throw new CoordinatorError('unknown_pairing');
    if (this.now() >= pairing.expires_at && !['trusted', 'rejected', 'expired'].includes(pairing.status)) {
      this.db.prepare("UPDATE pairings SET status = 'expired' WHERE pairing_id = ?").run(pairingId);
      throw new CoordinatorError('pairing_expired');
    }
    return pairing;
  }

  assertPairParticipant(pairing, auth) {
    const isHost = pairing.host_locator === auth.locator && pairing.host_fingerprint === auth.fingerprint;
    const isController = pairing.controller_locator === auth.locator && pairing.controller_fingerprint === auth.fingerprint;
    if (!isHost && !isController) throw new CoordinatorError('pairing_participant_denied');
    return { isHost, isController };
  }

  approvePairing(pairingId, host) {
    return this.transaction(() => {
      const pairing = this.getPairing(pairingId);
      const { isHost } = this.assertPairParticipant(pairing, host);
      if (!isHost) throw new CoordinatorError('pairing_approval_denied');
      if (pairing.status !== 'requested') throw new CoordinatorError('pairing_not_pending');
      const now = this.now();
      this.db.prepare("UPDATE pairings SET status = 'approved', host_approved_at = ? WHERE pairing_id = ?").run(now, pairingId);
      return { ...pairing, status: 'approved', host_approved_at: now };
    });
  }

  recordAttestation(pairingId, auth, signature, expiresAt) {
    return this.transaction(() => {
      const pairing = this.getPairing(pairingId);
      const roles = this.assertPairParticipant(pairing, auth);
      if (pairing.status !== 'approved') throw new CoordinatorError('pairing_not_approved');
      if (expiresAt !== pairing.expires_at) throw new CoordinatorError('attestation_expiry_mismatch');
      const peer = roles.isHost
        ? { locator: pairing.controller_locator, fingerprint: pairing.controller_fingerprint }
        : { locator: pairing.host_locator, fingerprint: pairing.host_fingerprint };
      const payload = {
        pairingId,
        sourceLocator: auth.locator,
        sourceFingerprint: auth.fingerprint,
        peerLocator: peer.locator,
        peerFingerprint: peer.fingerprint,
        expiresAt
      };
      if (!verifyTrustAttestation(signature, auth.signingPublicKey, payload)) {
        throw new CoordinatorError('invalid_trust_attestation_signature');
      }
      try {
        this.db.prepare(`INSERT INTO pairing_attestations
          (pairing_id, locator, fingerprint, signature, created_at) VALUES (?, ?, ?, ?, ?)`)
          .run(pairingId, auth.locator, auth.fingerprint, signature, this.now());
      } catch (error) {
        if (String(error.message).includes('UNIQUE constraint failed')) throw new CoordinatorError('duplicate_trust_attestation');
        throw error;
      }
      const attestations = this.db.prepare('SELECT * FROM pairing_attestations WHERE pairing_id = ?').all(pairingId);
      if (attestations.length !== 2) return { active: false, peer };
      const { left, right } = orderedLink(
        { locator: pairing.host_locator, fingerprint: pairing.host_fingerprint },
        { locator: pairing.controller_locator, fingerprint: pairing.controller_fingerprint }
      );
      this.db.prepare(`INSERT INTO trust_links
        (left_locator, left_fingerprint, right_locator, right_fingerprint, pairing_id, active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)`)
        .run(left.locator, left.fingerprint, right.locator, right.fingerprint, pairingId, this.now());
      this.db.prepare("UPDATE pairings SET status = 'trusted' WHERE pairing_id = ?").run(pairingId);
      return { active: true, peer };
    });
  }

  hasActiveTrust(source, destination) {
    return Boolean(this.db.prepare(`SELECT 1 FROM trust_links WHERE active = 1 AND
      ((left_locator = ? AND left_fingerprint = ? AND right_locator = ? AND right_fingerprint = ?) OR
       (right_locator = ? AND right_fingerprint = ? AND left_locator = ? AND left_fingerprint = ?))`)
      .get(source.locator, source.fingerprint, destination.locator, destination.fingerprint,
        source.locator, source.fingerprint, destination.locator, destination.fingerprint));
  }

  revokeTrust(source, destination) {
    const result = this.db.prepare(`UPDATE trust_links SET active = 0, revoked_at = ? WHERE active = 1 AND
      ((left_locator = ? AND left_fingerprint = ? AND right_locator = ? AND right_fingerprint = ?) OR
       (right_locator = ? AND right_fingerprint = ? AND left_locator = ? AND left_fingerprint = ?))`)
      .run(this.now(), source.locator, source.fingerprint, destination.locator, destination.fingerprint,
        source.locator, source.fingerprint, destination.locator, destination.fingerprint);
    if (result.changes !== 1) throw new CoordinatorError('trust_link_not_found');
  }

  close() {
    this.db.close();
  }
}

function safeSend(socket, message) {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

export function createCoordinator({ databasePath = ':memory:', now = () => Date.now(), limits = {}, turn } = {}) {
  const configuredLimits = {
    auth: { capacity: 20, refillPerMinute: 20, ...limits.auth },
    pairing: { capacity: 6, refillPerMinute: 6, ...limits.pairing },
    signal: { capacity: 60, refillPerMinute: 60, ...limits.signal }
  };
  const store = new CoordinatorStore(databasePath, now);
  const turnConfiguration = normalizeTurnConfiguration(turn);
  const rateLimiter = new TokenBucket();
  const connections = new Map();
  const byLocator = new Map();
  const webSocketServer = new WebSocketServer({ noServer: true, maxPayload: MAX_WS_MESSAGE_BYTES, perMessageDeflate: false });

  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200);
      res.end(JSON.stringify({ service: 'wii-ultra-desk-coordinator', status: 'ok',
        phase: 'authenticated-connectivity', remoteSessionsAvailable: false }));
      return;
    }
    if (req.headers['content-length'] && Number(req.headers['content-length']) > MAX_HTTP_BODY_BYTES) {
      res.writeHead(413);
      res.end(JSON.stringify({ error: 'request_too_large' }));
      req.resume();
      return;
    }
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'not_found' }));
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.coordinatorStore = store;

  function addAuthenticatedConnection(state) {
    const deviceConnections = byLocator.get(state.auth.locator) ?? new Set();
    if (deviceConnections.size >= MAX_DEVICE_CONNECTIONS) throw new CoordinatorError('device_connection_limit');
    deviceConnections.add(state);
    byLocator.set(state.auth.locator, deviceConnections);
  }

  function removeConnection(state) {
    connections.delete(state.connectionId);
    clearTimeout(state.challengeTimer);
    clearTimeout(state.sessionTimer);
    if (state.auth) {
      const deviceConnections = byLocator.get(state.auth.locator);
      deviceConnections?.delete(state);
      if (deviceConnections?.size === 0) byLocator.delete(state.auth.locator);
    }
  }

  function sendToDevice(locator, message) {
    for (const state of byLocator.get(locator) ?? []) safeSend(state.socket, message);
  }

  function peerForPairing(pairing, auth) {
    return pairing.host_locator === auth.locator
      ? { locator: pairing.controller_locator, fingerprint: pairing.controller_fingerprint }
      : { locator: pairing.host_locator, fingerprint: pairing.host_fingerprint };
  }

  function authenticateBegin(state, message) {
    requireExactKeys(message, ['bundle', 'type']);
    if (!rateLimiter.consume(`auth:${state.ip}`, configuredLimits.auth, now())) throw new CoordinatorError('rate_limited');
    if (state.pending) throw new CoordinatorError('authentication_already_pending');
    const bundle = verifyIdentityBundle(message.bundle);
    const nonce = crypto.randomBytes(32).toString('base64url');
    const expiresAt = now() + AUTH_CHALLENGE_TTL_MS;
    state.pending = { bundle, nonce, expiresAt };
    state.challengeTimer = setTimeout(() => {
      if (!state.auth) {
        safeSend(state.socket, { type: 'ERROR', code: 'authentication_challenge_expired' });
        state.socket.close(4001, 'authentication challenge expired');
      }
    }, AUTH_CHALLENGE_TTL_MS + 100);
    safeSend(state.socket, { type: 'AUTH_CHALLENGE', connectionId: state.connectionId, nonce, expiresAt });
  }

  function authenticateProve(state, message) {
    requireExactKeys(message, ['connectionId', 'expiresAt', 'nonce', 'signature', 'type']);
    if (!state.pending) throw new CoordinatorError('authentication_not_started');
    const pending = state.pending;
    if (now() > pending.expiresAt || message.connectionId !== state.connectionId ||
        message.nonce !== pending.nonce || message.expiresAt !== pending.expiresAt) {
      throw new CoordinatorError('authentication_challenge_invalid_or_expired');
    }
    const signature = Buffer.from(requireString(message.signature, { min: 86, max: 86, pattern: /^[A-Za-z0-9_-]+$/, code: 'invalid_authentication_signature' }), 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== message.signature ||
        !crypto.verify(null, authProofPayload({ connectionId: state.connectionId, nonce: pending.nonce,
          locator: pending.bundle.bundle.locator, fingerprint: pending.bundle.fingerprint, expiresAt: pending.expiresAt
        }), pending.bundle.publicKey, signature)) {
      throw new CoordinatorError('invalid_authentication_signature');
    }
    const registration = store.register(pending.bundle);
    state.auth = { locator: pending.bundle.bundle.locator, fingerprint: pending.bundle.fingerprint,
      signingPublicKey: pending.bundle.signingPublicKey, bundle: pending.bundle.bundle };
    state.pending = undefined;
    clearTimeout(state.challengeTimer);
    addAuthenticatedConnection(state);
    const expiresAt = now() + SESSION_TTL_MS;
    state.sessionTimer = setTimeout(() => {
      safeSend(state.socket, { type: 'ERROR', code: 'session_expired' });
      state.socket.close(4002, 'session expired');
    }, SESSION_TTL_MS + 100);
    safeSend(state.socket, { type: 'AUTH_OK', locator: state.auth.locator, fingerprint: state.auth.fingerprint,
      sessionExpiresAt: expiresAt, registration: registration.isNew ? 'created' : 'existing' });
  }

  function requireAuthenticated(state) {
    if (!state.auth) throw new CoordinatorError('authentication_required');
    return state.auth;
  }

  function handleAuthenticatedMessage(state, message) {
    const auth = requireAuthenticated(state);
    switch (message.type) {
      case 'PAIR_INVITE_CREATE': {
        requireExactKeys(message, ['ttlMs', 'type']);
        const ttlMs = requireSafeInteger(message.ttlMs, { min: 1_000, max: MAX_INVITATION_TTL_MS, code: 'invalid_invitation_ttl' });
        if (!rateLimiter.consume(`pairing:${auth.locator}`, configuredLimits.pairing, now())) throw new CoordinatorError('rate_limited');
        safeSend(state.socket, { type: 'PAIR_INVITE', ...store.createInvitation(auth, ttlMs),
          host: { locator: auth.locator, fingerprint: auth.fingerprint } });
        return;
      }
      case 'PAIR_REQUEST': {
        requireExactKeys(message, ['bundle', 'token', 'type']);
        if (!rateLimiter.consume(`pairing:${auth.locator}`, configuredLimits.pairing, now())) throw new CoordinatorError('rate_limited');
        const bundle = verifyIdentityBundle(message.bundle);
        if (bundle.fingerprint !== auth.fingerprint || bundle.bundle.locator !== auth.locator) {
          throw new CoordinatorError('pairing_bundle_does_not_match_authenticated_identity');
        }
        const token = requireString(message.token, { min: 43, max: 43, pattern: /^[A-Za-z0-9_-]+$/, code: 'invalid_invitation_token' });
        const pairing = store.reserveInvitation(token, auth);
        safeSend(state.socket, { type: 'PAIR_PENDING', pairingId: pairing.pairingId, expiresAt: pairing.expiresAt });
        sendToDevice(pairing.host.locator, { type: 'PAIR_REQUEST', pairingId: pairing.pairingId,
          expiresAt: pairing.expiresAt, controller: { locator: auth.locator, fingerprint: auth.fingerprint, bundle: auth.bundle } });
        return;
      }
      case 'PAIR_APPROVE': {
        requireExactKeys(message, ['pairingId', 'type']);
        const pairingId = requireString(message.pairingId, { min: 16, max: 128, code: 'invalid_pairing_id' });
        const pairing = store.approvePairing(pairingId, auth);
        // The controller needs the host's signed identity bundle to bind the
        // opaque Noise XX transcript to the authenticated coordinator peer.
        // It still verifies this self-signature and the Noise static key
        // locally; the coordinator is not a trust anchor.
        sendToDevice(peerForPairing(pairing, auth).locator, { type: 'PAIR_APPROVED', pairingId, expiresAt: pairing.expires_at,
          host: { locator: auth.locator, fingerprint: auth.fingerprint, bundle: auth.bundle } });
        return;
      }
      case 'PAIR_FRAME': {
        requireExactKeys(message, ['frame', 'pairingId', 'sequence', 'type']);
        const pairingId = requireString(message.pairingId, { min: 16, max: 128, code: 'invalid_pairing_id' });
        const sequence = requireSafeInteger(message.sequence, { min: 0, max: 4_294_967_295, code: 'invalid_pairing_sequence' });
        decodeOpaqueFrame(message.frame);
        const pairing = store.getPairing(pairingId);
        store.assertPairParticipant(pairing, auth);
        if (pairing.status !== 'approved') throw new CoordinatorError('pairing_not_approved');
        sendToDevice(peerForPairing(pairing, auth).locator, { type: 'PAIR_FRAME', pairingId, sequence, frame: message.frame,
          source: { locator: auth.locator, fingerprint: auth.fingerprint } });
        return;
      }
      case 'TRUST_ATTEST': {
        requireExactKeys(message, ['expiresAt', 'pairingId', 'signature', 'type']);
        const pairingId = requireString(message.pairingId, { min: 16, max: 128, code: 'invalid_pairing_id' });
        const expiresAt = requireSafeInteger(message.expiresAt, { code: 'invalid_attestation_expiry' });
        const signature = requireString(message.signature, { min: 86, max: 86, pattern: /^[A-Za-z0-9_-]+$/, code: 'invalid_trust_attestation_signature' });
        const result = store.recordAttestation(pairingId, auth, signature, expiresAt);
        safeSend(state.socket, { type: result.active ? 'TRUST_LINK_ACTIVE' : 'TRUST_ATTEST_RECORDED', pairingId, peer: result.peer });
        if (result.active) sendToDevice(result.peer.locator, { type: 'TRUST_LINK_ACTIVE', pairingId,
          peer: { locator: auth.locator, fingerprint: auth.fingerprint } });
        return;
      }
      case 'SIGNAL': {
        requireExactKeys(message, ['destination', 'payload', 'type']);
        if (!rateLimiter.consume(`signal:${auth.locator}`, configuredLimits.signal, now())) throw new CoordinatorError('rate_limited');
        const destination = requireDestination(message.destination);
        const payload = requireSignalPayload(message.payload);
        if (!store.hasActiveTrust(auth, destination)) throw new CoordinatorError('signaling_destination_not_authorized');
        if (!(byLocator.get(destination.locator)?.size > 0)) throw new CoordinatorError('signaling_destination_offline');
        sendToDevice(destination.locator, { type: 'SIGNAL', source: { locator: auth.locator, fingerprint: auth.fingerprint }, payload });
        return;
      }
      case 'TURN_CREDENTIAL_REQUEST': {
        requireExactKeys(message, ['capability', 'destination', 'sessionId', 'ttlMs', 'type']);
        if (!turnConfiguration) throw new CoordinatorError('turn_not_configured');
        if (!rateLimiter.consume(`signal:${auth.locator}`, configuredLimits.signal, now())) throw new CoordinatorError('rate_limited');
        const destination = requireDestination(message.destination);
        const sessionId = requireSessionId(message.sessionId);
        const ttlMs = requireSafeInteger(message.ttlMs, {
          min: MIN_TURN_CREDENTIAL_TTL_MS,
          max: MAX_TURN_CREDENTIAL_TTL_MS,
          code: 'invalid_turn_credential_ttl'
        });
        if (message.capability !== STATUS_CAPABILITY) throw new CoordinatorError('capability_not_authorized');
        if (!store.hasActiveTrust(auth, destination)) throw new CoordinatorError('signaling_destination_not_authorized');
        const expiresAt = now() + ttlMs;
        safeSend(state.socket, {
          type: 'TURN_CREDENTIALS', sessionId, expiresAt,
          iceServers: [turnCredential(turnConfiguration, auth, sessionId, expiresAt)]
        });
        return;
      }
      case 'PRESENCE_QUERY': {
        requireExactKeys(message, ['destination', 'type']);
        const destination = requireDestination(message.destination);
        if (!store.hasActiveTrust(auth, destination)) throw new CoordinatorError('presence_destination_not_authorized');
        safeSend(state.socket, { type: 'PRESENCE_RESULT', destination, online: (byLocator.get(destination.locator)?.size ?? 0) > 0 });
        return;
      }
      case 'TRUST_REVOKE': {
        requireExactKeys(message, ['destination', 'type']);
        const destination = requireDestination(message.destination);
        store.revokeTrust(auth, destination);
        safeSend(state.socket, { type: 'TRUST_REVOKED', destination });
        sendToDevice(destination.locator, { type: 'TRUST_REVOKED', destination: { locator: auth.locator, fingerprint: auth.fingerprint } });
        return;
      }
      default:
        throw new CoordinatorError('unknown_or_unauthorized_message');
    }
  }

  webSocketServer.on('connection', (socket, request) => {
    const state = { socket, ip: remoteAddress(request), connectionId: crypto.randomUUID(), pending: undefined,
      auth: undefined, challengeTimer: undefined, sessionTimer: undefined };
    connections.set(state.connectionId, state);
    socket.on('message', (raw, isBinary) => {
      try {
        if (isBinary || Buffer.byteLength(raw) > MAX_WS_MESSAGE_BYTES) throw new CoordinatorError('message_too_large_or_binary');
        const message = JSON.parse(raw.toString('utf8'));
        requireObject(message);
        requireString(message.type, { min: 1, max: 64, pattern: /^[A-Z_]+$/, code: 'invalid_message_type' });
        if (!state.auth && message.type === 'AUTH_BEGIN') authenticateBegin(state, message);
        else if (!state.auth && message.type === 'AUTH_PROVE') authenticateProve(state, message);
        else handleAuthenticatedMessage(state, message);
      } catch (error) {
        const code = error instanceof CoordinatorError || error instanceof ProtocolError ? error.code : 'invalid_message';
        safeSend(socket, { type: 'ERROR', code });
      }
    });
    socket.on('close', () => removeConnection(state));
    socket.on('error', () => removeConnection(state));
  });

  server.on('upgrade', (request, socket, head) => {
    if (request.url !== '/v1/connect' || connections.size >= MAX_CONNECTIONS) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    webSocketServer.handleUpgrade(request, socket, head, upgraded => webSocketServer.emit('connection', upgraded, request));
  });
  server.on('close', () => {
    for (const state of connections.values()) state.socket.terminate();
    webSocketServer.close();
    store.close();
  });
  server.stop = callback => {
    for (const state of connections.values()) state.socket.terminate();
    server.close(callback);
  };
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 4310);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const databasePath = process.env.WII_COORDINATOR_DB || 'coordinator.sqlite';
  const turnUrls = process.env.WII_TURN_URLS?.split(',').map(value => value.trim()).filter(Boolean);
  const turn = process.env.WII_TURN_SHARED_SECRET && turnUrls?.length
    ? { sharedSecret: process.env.WII_TURN_SHARED_SECRET, urls: turnUrls }
    : undefined;
  const server = createCoordinator({ databasePath, turn });
  // Deliberately loopback-only: production exposure is through reviewed HTTPS/WSS ingress.
  server.listen(port, '127.0.0.1', () => console.log(`Coordinator: ws://127.0.0.1:${port}/v1/connect`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
}
