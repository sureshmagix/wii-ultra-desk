import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createCoordinator } from '../services/coordinator/server.mjs';
import { createDevelopmentIdentity, signAuthProof, signTrustAttestation } from '../packages/protocol/identity.mjs';
import { CoordinatorClient } from './helpers/coordinator-client.mjs';

async function startCoordinator(t, options = {}) {
  const server = createCoordinator(options);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.stop(resolve));
  });
  return `ws://127.0.0.1:${server.address().port}/v1/connect`;
}

async function authenticatedClient(t, url, identity) {
  const client = new CoordinatorClient(url, identity);
  t.after(() => client.close());
  const result = await client.authenticate();
  assert.equal(result.type, 'AUTH_OK', result.code);
  return client;
}

test('rejects spoofed authentication, replayed challenges, malformed bundles, and substituted identity keys', async t => {
  const url = await startCoordinator(t);
  const identity = createDevelopmentIdentity();
  const legitimate = await authenticatedClient(t, url, identity);

  const spoof = new CoordinatorClient(url);
  t.after(() => spoof.close());
  await spoof.send({ type: 'AUTH_BEGIN', bundle: { ...spoof.identity.bundle, authenticated: true } });
  assert.equal((await spoof.waitForType('ERROR')).code, 'invalid_identity_bundle');

  const invalidCredential = new CoordinatorClient(url);
  t.after(() => invalidCredential.close());
  await invalidCredential.send({ type: 'AUTH_BEGIN', bundle: invalidCredential.identity.bundle });
  const invalidChallenge = await invalidCredential.waitForType('AUTH_CHALLENGE');
  await invalidCredential.send({
    type: 'AUTH_PROVE',
    connectionId: invalidChallenge.connectionId,
    nonce: invalidChallenge.nonce,
    expiresAt: invalidChallenge.expiresAt,
    signature: signAuthProof(identity, {
      connectionId: invalidChallenge.connectionId,
      nonce: invalidChallenge.nonce,
      locator: invalidCredential.identity.bundle.locator,
      fingerprint: invalidCredential.identity.fingerprint,
      expiresAt: invalidChallenge.expiresAt
    })
  });
  assert.equal((await invalidCredential.waitForType('ERROR')).code, 'invalid_authentication_signature');

  const first = new CoordinatorClient(url, identity);
  const second = new CoordinatorClient(url, identity);
  t.after(() => first.close());
  t.after(() => second.close());
  await first.send({ type: 'AUTH_BEGIN', bundle: identity.bundle });
  const firstChallenge = await first.waitForType('AUTH_CHALLENGE');
  await second.send({ type: 'AUTH_BEGIN', bundle: identity.bundle });
  const secondChallenge = await second.waitForType('AUTH_CHALLENGE');
  await second.send({
    type: 'AUTH_PROVE',
    connectionId: firstChallenge.connectionId,
    nonce: firstChallenge.nonce,
    expiresAt: firstChallenge.expiresAt,
    signature: signAuthProof(identity, {
      connectionId: firstChallenge.connectionId,
      nonce: firstChallenge.nonce,
      locator: identity.bundle.locator,
      fingerprint: identity.fingerprint,
      expiresAt: firstChallenge.expiresAt
    })
  });
  assert.equal((await second.waitForType('ERROR')).code, 'authentication_challenge_invalid_or_expired');
  assert.notEqual(secondChallenge.nonce, firstChallenge.nonce);

  const replacement = createDevelopmentIdentity({ locator: identity.bundle.locator });
  const attacker = new CoordinatorClient(url, replacement);
  t.after(() => attacker.close());
  await attacker.send({ type: 'AUTH_BEGIN', bundle: replacement.bundle });
  const challenge = await attacker.waitForType('AUTH_CHALLENGE');
  await attacker.send({
    type: 'AUTH_PROVE',
    connectionId: challenge.connectionId,
    nonce: challenge.nonce,
    expiresAt: challenge.expiresAt,
    signature: signAuthProof(replacement, {
      connectionId: challenge.connectionId,
      nonce: challenge.nonce,
      locator: replacement.bundle.locator,
      fingerprint: replacement.fingerprint,
      expiresAt: challenge.expiresAt
    })
  });
  assert.equal((await attacker.waitForType('ERROR')).code, 'identity_mismatch');
  assert.equal(legitimate.identity.fingerprint, identity.fingerprint);
});

test('requires host approval and bilateral signed trust attestations before routing signals', async t => {
  const url = await startCoordinator(t);
  const host = await authenticatedClient(t, url);
  const controller = await authenticatedClient(t, url);

  await host.send({ type: 'PAIR_INVITE_CREATE', ttlMs: 60_000 });
  const invitation = await host.waitForType('PAIR_INVITE');
  await controller.send({ type: 'PAIR_REQUEST', token: invitation.token, bundle: controller.identity.bundle });
  const pending = await controller.waitForType('PAIR_PENDING');
  const request = await host.waitForType('PAIR_REQUEST');
  assert.equal(request.pairingId, pending.pairingId);
  assert.equal(request.controller.fingerprint, controller.identity.fingerprint);

  await controller.send({ type: 'PAIR_FRAME', pairingId: pending.pairingId, sequence: 0, frame: Buffer.from('not-noise-yet').toString('base64url') });
  assert.equal((await controller.waitForType('ERROR')).code, 'pairing_not_approved');

  await host.send({ type: 'PAIR_APPROVE', pairingId: pending.pairingId });
  await controller.waitForType('PAIR_APPROVED');
  // This only proves the coordinator relays opaque bytes after local host approval.
  // It is not presented as a completed Noise pairing or a remote-access session.
  await controller.send({ type: 'PAIR_FRAME', pairingId: pending.pairingId, sequence: 1, frame: Buffer.from('opaque-test-frame').toString('base64url') });
  assert.equal((await host.waitForType('PAIR_FRAME')).source.fingerprint, controller.identity.fingerprint);

  const controllerAttestation = {
    pairingId: pending.pairingId,
    sourceLocator: controller.identity.bundle.locator,
    sourceFingerprint: controller.identity.fingerprint,
    peerLocator: host.identity.bundle.locator,
    peerFingerprint: host.identity.fingerprint,
    expiresAt: pending.expiresAt
  };
  const hostAttestation = {
    pairingId: pending.pairingId,
    sourceLocator: host.identity.bundle.locator,
    sourceFingerprint: host.identity.fingerprint,
    peerLocator: controller.identity.bundle.locator,
    peerFingerprint: controller.identity.fingerprint,
    expiresAt: pending.expiresAt
  };
  await controller.send({ type: 'TRUST_ATTEST', pairingId: pending.pairingId, expiresAt: pending.expiresAt,
    signature: signTrustAttestation(controller.identity, controllerAttestation) });
  assert.equal((await controller.waitForType('TRUST_ATTEST_RECORDED')).pairingId, pending.pairingId);
  await host.send({ type: 'TRUST_ATTEST', pairingId: pending.pairingId, expiresAt: pending.expiresAt,
    signature: signTrustAttestation(host.identity, hostAttestation) });
  await host.waitForType('TRUST_LINK_ACTIVE');
  await controller.waitForType('TRUST_LINK_ACTIVE');

  await controller.send({ type: 'SIGNAL', destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint },
    payload: { kind: 'webrtc.offer', data: Buffer.from('not-a-webrtc-session').toString('base64url') } });
  const signal = await host.waitForType('SIGNAL');
  assert.equal(signal.source.fingerprint, controller.identity.fingerprint);
  assert.equal(signal.payload.kind, 'webrtc.offer');

  // Lifecycle messages use the same authenticated, trusted-peer routing
  // boundary. The native host still verifies the signed envelope and sends an
  // acknowledgement before a controller may report revocation complete.
  await controller.send({ type: 'SIGNAL', destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint },
    payload: { kind: 'control.revocation', data: Buffer.from('bounded-lifecycle-envelope').toString('base64url') } });
  const revocation = await host.waitForType('SIGNAL');
  assert.equal(revocation.payload.kind, 'control.revocation');
  assert.equal(revocation.source.fingerprint, controller.identity.fingerprint);

  await host.send({ type: 'TRUST_REVOKE', destination: { locator: controller.identity.bundle.locator, fingerprint: controller.identity.fingerprint } });
  await host.waitForType('TRUST_REVOKED');
  await controller.waitForType('TRUST_REVOKED');
  await controller.send({ type: 'SIGNAL', destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint },
    payload: { kind: 'webrtc.offer', data: 'dGVzdA' } });
  assert.equal((await controller.waitForType('ERROR')).code, 'signaling_destination_not_authorized');
});

test('rejects expired invitations, pairing-rate exhaustion, unauthorized signaling, and malformed frames', async t => {
  let currentTime = 1_000_000;
  const url = await startCoordinator(t, { now: () => currentTime, limits: { pairing: { capacity: 1, refillPerMinute: 0 } } });
  const host = await authenticatedClient(t, url, createDevelopmentIdentity({ createdAt: currentTime }));
  const controller = await authenticatedClient(t, url, createDevelopmentIdentity({ createdAt: currentTime }));

  await controller.send({ type: 'SIGNAL', destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint },
    payload: { kind: 'webrtc.offer', data: 'dGVzdA' } });
  assert.equal((await controller.waitForType('ERROR')).code, 'signaling_destination_not_authorized');

  await host.send({ type: 'PAIR_INVITE_CREATE', ttlMs: 1_000 });
  const invitation = await host.waitForType('PAIR_INVITE');
  currentTime += 1_001;
  await controller.send({ type: 'PAIR_REQUEST', token: invitation.token, bundle: controller.identity.bundle });
  assert.equal((await controller.waitForType('ERROR')).code, 'invitation_invalid_or_expired');
  await host.send({ type: 'PAIR_INVITE_CREATE', ttlMs: 1_000 });
  assert.equal((await host.waitForType('ERROR')).code, 'rate_limited');

  await controller.send({ type: 'PAIR_FRAME', pairingId: 'bad', sequence: -1, frame: '*' });
  assert.equal((await controller.waitForType('ERROR')).code, 'invalid_pairing_id');
});

test('persists a registered identity across coordinator restart and rejects substitution', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-desk-coordinator-'));
  const databasePath = path.join(directory, 'coordinator.sqlite');
  const identity = createDevelopmentIdentity();
  const firstServer = createCoordinator({ databasePath });
  await new Promise(resolve => firstServer.listen(0, '127.0.0.1', resolve));
  const first = new CoordinatorClient(`ws://127.0.0.1:${firstServer.address().port}/v1/connect`, identity);
  assert.equal((await first.authenticate()).registration, 'created');
  await first.close();
  await new Promise(resolve => firstServer.close(resolve));

  const secondServer = createCoordinator({ databasePath });
  await new Promise(resolve => secondServer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => secondServer.stop(resolve)));
  const second = new CoordinatorClient(`ws://127.0.0.1:${secondServer.address().port}/v1/connect`, identity);
  t.after(() => second.close());
  assert.equal((await second.authenticate()).registration, 'existing');

  const replacement = createDevelopmentIdentity({ locator: identity.bundle.locator });
  const attacker = new CoordinatorClient(`ws://127.0.0.1:${secondServer.address().port}/v1/connect`, replacement);
  t.after(() => attacker.close());
  assert.equal((await attacker.authenticate()).code, 'identity_mismatch');
});
