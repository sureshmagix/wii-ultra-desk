import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { validateBookmark } = createRequire(import.meta.url)('../apps/desktop/validation.cjs');
test('bookmarks cannot carry credentials or grant unattended access', () => {
  assert.deepEqual(validateBookmark({ name: ' Office ', deviceId: 'office-001',
    password: 'secret', unattended: true, fingerprint: 'forged' }),
  { name: 'Office', deviceId: 'office-001' });
});
test('rejects malformed bookmark identifiers and names', () => {
  for (const deviceId of ['../escape', '', 'ssh://host', 42, 'x'.repeat(81)]) {
    assert.throws(() => validateBookmark({ name: 'Device', deviceId }));
  }
  assert.throws(() => validateBookmark({ name: '\n', deviceId: 'valid-id' }));
});
