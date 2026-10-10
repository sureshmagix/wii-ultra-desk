import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

const execFile = promisify(execFileCallback);
const generator = path.join(process.cwd(), 'scripts/utho/generate-coturn-config.mjs');

function environment(directory, changes = {}) {
  const values = {
    WII_TURN_SHARED_SECRET: '7fW5u9Xk2cL8rQ1mN4vB6aD3eG0hJpS_tYzKxCwRQk2',
    WII_TURN_FQDN: 'turn.staging.test',
    WII_TURN_REALM: 'turn.staging.test',
    WII_TURN_LISTEN_IP: '0.0.0.0',
    WII_TURN_RELAY_IP: '10.20.30.40',
    WII_TURN_PUBLIC_IP: '8.8.8.8',
    WII_TURN_PORT: '3478',
    WII_TURN_TLS_PORT: '5349',
    WII_TURN_RELAY_MIN_PORT: '49160',
    WII_TURN_RELAY_MAX_PORT: '49200',
    WII_TURN_USER_QUOTA: '2',
    WII_TURN_TOTAL_QUOTA: '64',
    WII_TURN_TLS_CERT: path.join(directory, 'fullchain.pem'),
    WII_TURN_TLS_KEY: path.join(directory, 'privkey.pem'),
    WII_TURN_URLS: 'turn:turn.staging.test:3478?transport=udp,turn:turn.staging.test:3478?transport=tcp,turns:turn.staging.test:5349?transport=tcp',
    ...changes
  };
  return `${Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n')}\n`;
}

test('production coturn generator emits a protected REST/TLS configuration only from valid runtime input', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-turn-config-'));
  const environmentPath = path.join(directory, 'staging.env');
  const output = path.join(directory, 'turnserver.conf');
  t.after(async () => { await (await import('node:fs/promises')).rm(directory, { recursive: true, force: true }); });
  await Promise.all([
    writeFile(path.join(directory, 'fullchain.pem'), 'test certificate'),
    writeFile(path.join(directory, 'privkey.pem'), 'test key')
  ]);
  await writeFile(environmentPath, environment(directory), { mode: 0o600 });
  await execFile(process.execPath, [generator, '--env', environmentPath, '--out', output]);
  const generated = await readFile(output, 'utf8');
  assert.match(generated, /^use-auth-secret$/m);
  assert.match(generated, /^external-ip=8\.8\.8\.8\/10\.20\.30\.40$/m);
  assert.match(generated, /^tls-listening-port=5349$/m);
  assert.match(generated, /^denied-peer-ip=169\.254\.0\.0-169\.254\.255\.255$/m);
  assert.doesNotMatch(generated, /REPLACE|example|placeholder/i);
});

test('production coturn generator rejects weak secrets, placeholders, malformed URLs, and unsafe listener settings', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-turn-invalid-'));
  const environmentPath = path.join(directory, 'staging.env');
  const output = path.join(directory, 'turnserver.conf');
  t.after(async () => { await (await import('node:fs/promises')).rm(directory, { recursive: true, force: true }); });
  await Promise.all([
    writeFile(path.join(directory, 'fullchain.pem'), 'test certificate'),
    writeFile(path.join(directory, 'privkey.pem'), 'test key')
  ]);
  for (const changes of [
    { WII_TURN_SHARED_SECRET: 'a'.repeat(43) },
    { WII_TURN_FQDN: 'turn.example.invalid', WII_TURN_REALM: 'turn.example.invalid' },
    { WII_TURN_URLS: 'turn:turn.staging.test:3478?transport=udp' },
    { WII_TURN_LISTEN_IP: '127.0.0.1' },
    { WII_TURN_PUBLIC_IP: '', WII_TURN_RELAY_IP: '10.20.30.40' },
    { WII_TURN_TLS_PORT: '443' }
  ]) {
    await writeFile(environmentPath, environment(directory, changes), { mode: 0o600 });
    await assert.rejects(
      execFile(process.execPath, [generator, '--env', environmentPath, '--out', output]),
      /coturn staging configuration rejected/
    );
  }
});
