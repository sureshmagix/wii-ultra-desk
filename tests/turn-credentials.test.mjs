import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { createCoordinator } from '../services/coordinator/server.mjs';
import { signTrustAttestation } from '../packages/protocol/identity.mjs';
import { CoordinatorClient } from './helpers/coordinator-client.mjs';

const TURN_SECRET = 'development-turn-secret-that-is-never-a-production-secret';
const sessionId = Buffer.alloc(16, 7).toString('base64url');

async function start(t, options = {}) {
  const server = createCoordinator(options);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.stop(resolve)));
  return `ws://127.0.0.1:${server.address().port}/v1/connect`;
}

async function client(t, url) {
  const instance = new CoordinatorClient(url);
  t.after(() => instance.close());
  assert.equal((await instance.authenticate()).type, 'AUTH_OK');
  return instance;
}

async function establishTrust(host, controller) {
  await host.send({ type: 'PAIR_INVITE_CREATE', ttlMs: 60_000 });
  const invitation = await host.waitForType('PAIR_INVITE');
  await controller.send({ type: 'PAIR_REQUEST', token: invitation.token, bundle: controller.identity.bundle });
  const pending = await controller.waitForType('PAIR_PENDING');
  await host.waitForType('PAIR_REQUEST');
  await host.send({ type: 'PAIR_APPROVE', pairingId: pending.pairingId });
  await controller.waitForType('PAIR_APPROVED');
  for (const [source, peer] of [[host, controller], [controller, host]]) {
    const attestation = {
      pairingId: pending.pairingId,
      sourceLocator: source.identity.bundle.locator,
      sourceFingerprint: source.identity.fingerprint,
      peerLocator: peer.identity.bundle.locator,
      peerFingerprint: peer.identity.fingerprint,
      expiresAt: pending.expiresAt
    };
    await source.send({ type: 'TRUST_ATTEST', pairingId: pending.pairingId, expiresAt: pending.expiresAt,
      signature: signTrustAttestation(source.identity, attestation) });
    await source.waitFor(message => message.type === 'TRUST_ATTEST_RECORDED' || message.type === 'TRUST_LINK_ACTIVE');
  }
  await host.waitForType('TRUST_LINK_ACTIVE');
}

test('issues a scoped short-lived coturn REST credential only to a trusted authenticated peer', async t => {
  let clock = 2_000_000;
  const url = await start(t, {
    now: () => clock,
    turn: { sharedSecret: TURN_SECRET, urls: ['turn:127.0.0.1:3478?transport=udp'] }
  });
  const host = await client(t, url);
  const controller = await client(t, url);
  await establishTrust(host, controller);
  await controller.send({
    type: 'TURN_CREDENTIAL_REQUEST', capability: 'desktop.view', sessionId, ttlMs: 60_000,
    destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint }
  });
  const credential = await controller.waitForType('TURN_CREDENTIALS');
  assert.equal(credential.sessionId, sessionId);
  assert.equal(credential.expiresAt, clock + 60_000);
  assert.equal(credential.iceServers.length, 1);
  assert.equal(credential.iceServers[0].urls[0], 'turn:127.0.0.1:3478?transport=udp');
  assert.match(credential.iceServers[0].username, /^2060:/);
  assert.equal(
    credential.iceServers[0].credential,
    crypto.createHmac('sha1', TURN_SECRET).update(credential.iceServers[0].username).digest('base64')
  );
  assert.notEqual(credential.iceServers[0].credential, TURN_SECRET);

  await controller.send({
    type: 'TURN_CREDENTIAL_REQUEST', capability: 'ssh', sessionId, ttlMs: 60_000,
    destination: { locator: host.identity.bundle.locator, fingerprint: host.identity.fingerprint }
  });
  assert.equal((await controller.waitForType('ERROR')).code, 'capability_not_authorized');

  clock += 60_001;
  assert.ok(credential.expiresAt < clock, 'credential expiry is externally observable and bounded');
});

test('does not issue TURN credentials to an unauthorized peer or without explicit coordinator configuration', async t => {
  const noTurnUrl = await start(t);
  const noTurnClient = await client(t, noTurnUrl);
  await noTurnClient.send({
    type: 'TURN_CREDENTIAL_REQUEST', capability: 'desktop.view', sessionId, ttlMs: 60_000,
    destination: { locator: noTurnClient.identity.bundle.locator, fingerprint: noTurnClient.identity.fingerprint }
  });
  assert.equal((await noTurnClient.waitForType('ERROR')).code, 'turn_not_configured');

  const configuredUrl = await start(t, {
    turn: { sharedSecret: TURN_SECRET, urls: ['turn:127.0.0.1:3478?transport=udp'] }
  });
  const attacker = await client(t, configuredUrl);
  const target = await client(t, configuredUrl);
  await attacker.send({
    type: 'TURN_CREDENTIAL_REQUEST', capability: 'desktop.view', sessionId, ttlMs: 60_000,
    destination: { locator: target.identity.bundle.locator, fingerprint: target.identity.fingerprint }
  });
  assert.equal((await attacker.waitForType('ERROR')).code, 'signaling_destination_not_authorized');
});
