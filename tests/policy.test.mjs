import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeUnattended } from '../packages/policy/unattended.mjs';
const fp = 'a'.repeat(64);
function fixture() {
  return { now: 1000, capability: 'desktop.view', peer: { authenticated: true, fingerprint: fp },
    policy: { enabled: true, grants: [{ fingerprint: fp, revoked: false, notBefore: 100,
      expiresAt: 2000, capabilities: ['desktop.view'] }] } };
}
test('fails closed without a configured policy', () => assert.equal(authorizeUnattended().allowed, false));
test('allows a current authenticated scoped grant', () => assert.equal(authorizeUnattended(fixture()).allowed, true));
test('denies unauthenticated and different devices', () => {
  for (const peer of [{ authenticated: false, fingerprint: fp },
    { authenticated: true, fingerprint: 'b'.repeat(64) }, { authenticated: true, fingerprint: 'invalid' }]) {
    assert.equal(authorizeUnattended({ ...fixture(), peer }).allowed, false);
  }
});
test('view permission does not grant control, SSH or file access', () => {
  for (const capability of ['desktop.control', 'ssh', 'files.read', 'files.write', 'arbitrary']) {
    assert.equal(authorizeUnattended({ ...fixture(), capability }).allowed, false);
  }
});
test('expiry and not-before boundaries fail closed', () => {
  for (const now of [99, 2000, 2001, NaN, -1]) assert.equal(authorizeUnattended({ ...fixture(), now }).allowed, false);
});
test('rechecking after revocation or global disable denies access', () => {
  const data = fixture();
  assert.equal(authorizeUnattended(data).allowed, true);
  data.policy.grants[0].revoked = true;
  assert.equal(authorizeUnattended(data).allowed, false);
  data.policy.grants[0].revoked = false;
  data.policy.enabled = false;
  assert.equal(authorizeUnattended(data).allowed, false);
});
test('duplicate and malformed grants cannot authorize', () => {
  const data = fixture();
  data.policy.grants.push({ ...data.policy.grants[0] });
  assert.equal(authorizeUnattended(data).allowed, false);
  data.policy.grants = [null, {}];
  assert.equal(authorizeUnattended(data).allowed, false);
});
