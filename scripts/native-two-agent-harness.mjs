import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createCoordinator } from '../services/coordinator/server.mjs';

const cargo = process.env.CARGO || 'cargo';

function runAgent(url, stateDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(cargo, [
      'run', '--manifest-path', 'agent/Cargo.toml', '--locked', '--',
      'coordinator-status', '--state-dir', stateDir, '--coordinator', url
    ], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => {
      if (code !== 0) return reject(new Error(`native agent exited ${code}: ${stderr}`));
      const result = stdout.trim().split('\n').find(line => line.startsWith('{'));
      if (!result) return reject(new Error(`native agent returned no status: ${stderr}`));
      resolve(JSON.parse(result));
    });
  });
}

const coordinator = createCoordinator();
await new Promise(resolve => coordinator.listen(0, '127.0.0.1', resolve));
const url = `ws://127.0.0.1:${coordinator.address().port}/v1/connect`;
const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-desk-native-two-agent-'));

try {
  const [host, controller] = await Promise.all([
    runAgent(url, path.join(directory, 'host')),
    runAgent(url, path.join(directory, 'controller'))
  ]);
  assert.equal(host.coordinator, 'authenticated');
  assert.equal(controller.coordinator, 'authenticated');
  assert.equal(host.remote_access, false);
  assert.equal(controller.remote_access, false);
  console.log('Two native agents completed independent signed coordinator authentications.');
  console.log('This harness does not pair devices, create trust, request TURN credentials, or claim a WebRTC session.');
} finally {
  await new Promise(resolve => coordinator.stop(resolve));
  await rm(directory, { recursive: true, force: true });
}
