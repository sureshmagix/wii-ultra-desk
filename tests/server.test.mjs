import test from 'node:test';
import assert from 'node:assert/strict';
import { createCoordinator } from '../services/coordinator/server.mjs';
test('health works; remote access routes do not exist', async t => {
  const server = createCoordinator();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const health = await fetch(`${base}/healthz`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).remoteSessionsAvailable, false);
  assert.equal(health.headers.get('cache-control'), 'no-store');
  for (const route of ['/connect', '/register', '/ssh', '/files']) {
    assert.equal((await fetch(base + route, { method: 'POST' })).status, 404);
  }
});
