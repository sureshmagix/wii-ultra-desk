import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createCoordinator } from '../services/coordinator/server.mjs';

const cargo = process.env.CARGO || 'cargo';
const builtAgent = process.env.WII_AGENT_BINARY || path.join(process.cwd(), 'agent', 'target', 'debug', 'wii-ultra-desk-agent');
const coordinator = createCoordinator();
await new Promise(resolve => coordinator.listen(0, '127.0.0.1', resolve));
const coordinatorUrl = `ws://127.0.0.1:${coordinator.address().port}/v1/connect`;
const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-desk-unattended-'));
let hostPairing;
let controllerPairing;
let daemon;

function agent(args, stateDir) {
  const invocation = existsSync(builtAgent)
    ? [builtAgent, [...args, '--state-dir', stateDir]]
    : [cargo, ['run', '--manifest-path', 'agent/Cargo.toml', '--locked', '--', ...args, '--state-dir', stateDir]];
  const child = spawn(invocation[0], invocation[1], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  const waiters = [];
  const check = () => {
    for (const waiter of [...waiters]) {
      const match = waiter.pattern.exec(`${stdout}\n${stderr}`);
      if (match) {
        clearTimeout(waiter.timer);
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve(match);
      }
    }
  };
  child.stdout.on('data', value => { stdout += value.toString(); check(); });
  child.stderr.on('data', value => { stderr += value.toString(); check(); });
  const exited = new Promise((resolve, reject) => child.once('close', code => code === 0 ? resolve() : reject(new Error(`${args[0]} exited ${code}: ${stderr}`))));
  exited.catch(() => {});
  return {
    child,
    exited,
    json() {
      const line = stdout.trim().split('\n').findLast(value => value.startsWith('{') || value.startsWith('['));
      return line ? JSON.parse(line) : undefined;
    },
    logs() { return `${stdout}\n${stderr}`; },
    wait(pattern, timeoutMs = 20_000) {
      const match = pattern.exec(`${stdout}\n${stderr}`);
      if (match) return Promise.resolve(match);
      return new Promise((resolve, reject) => {
        const waiter = { pattern, resolve, timer: setTimeout(() => reject(new Error(`Timed out waiting for ${pattern}:\n${stdout}\n${stderr}`)), timeoutMs) };
        waiters.push(waiter);
      });
    },
    stop() { child.kill('SIGTERM'); }
  };
}

async function toExit(args, stateDir) {
  const process = agent(args, stateDir);
  await process.exited;
  return process.json();
}

function localSocket(socketPath, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let output = '';
    socket.setTimeout(3_000);
    socket.once('connect', () => socket.end(`${JSON.stringify(request)}\n`));
    socket.on('data', value => { output += value; });
    socket.once('timeout', () => reject(new Error('local control request timed out')));
    socket.once('error', reject);
    socket.once('close', () => {
      try { resolve(JSON.parse(output)); } catch { reject(new Error(`invalid local control response: ${output}`)); }
    });
  });
}

async function waitForSocket(socketPath, timeoutMs = 3_000) {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(socketPath)) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for local-control socket: ${socketPath}`);
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

try {
  const hostState = path.join(directory, 'host');
  const controllerState = path.join(directory, 'controller');
  hostPairing = agent(['pair-host', '--coordinator', coordinatorUrl, '--name', 'Lifecycle controller'], hostState);
  const token = (await hostPairing.wait(/Pairing invitation token .*: ([A-Za-z0-9_-]{43})/))[1];
  controllerPairing = agent(['pair-controller', '--coordinator', coordinatorUrl, '--token', token, '--name', 'Lifecycle host'], controllerState);
  const [hostSas, controllerSas] = await Promise.all([
    hostPairing.wait(/Pairing SAS: ([0-9-]{35})/),
    controllerPairing.wait(/Pairing SAS: ([0-9-]{35})/)
  ]);
  assert.equal(hostSas[1], controllerSas[1]);
  hostPairing.child.stdin.write(`${hostSas[1]}\n`);
  controllerPairing.child.stdin.write(`${controllerSas[1]}\n`);
  await Promise.all([hostPairing.exited, controllerPairing.exited]);
  const hostPair = hostPairing.json();
  const controllerPair = controllerPairing.json();
  assert.equal(hostPair.pairing, 'trusted');
  assert.equal(controllerPair.pairing, 'trusted');

  // The daemon runs without Electron. It begins with unattended disabled and
  // its local socket rejects a malformed privileged action.
  daemon = agent(['daemon', '--coordinator', coordinatorUrl], hostState);
  await daemon.wait(/"service":"ready"/);
  const socketPath = daemon.json()?.localControl;
  assert.equal(typeof socketPath, 'string');
  await waitForSocket(socketPath);
  const initial = await localSocket(socketPath, { action: 'status', version: 1 });
  assert.equal(initial.ok, true);
  assert.equal(initial.status.enabled, false);
  const rejected = await localSocket(socketPath, { action: 'disable', version: 1, confirmation: 'wrong' });
  assert.equal(rejected.ok, false, 'malformed local IPC must not disable access');

  // Give the daemon time to complete its authenticated coordinator connection
  // before requesting signed remote revocation from the paired controller.
  await new Promise(resolve => setTimeout(resolve, 1_000));
  const revocation = await toExit(['remote-revoke-peer', '--coordinator', coordinatorUrl,
    '--peer-locator', controllerPair.peerLocator, '--peer-fingerprint', controllerPair.peerFingerprint], controllerState);
  assert.equal(revocation.state, 'acknowledged');
  const devices = await toExit(['trusted-devices'], hostState);
  const revoked = devices.find(device => device.fingerprint === hostPair.peerFingerprint);
  assert.equal(revoked?.revoked, true, 'host must acknowledge only after local identity revocation');
  console.log('Native daemon stayed independent of Electron, rejected malformed local IPC, and acknowledged signed remote revocation after host-side termination state changed.');
} finally {
  for (const process of [hostPairing, controllerPairing, daemon]) process?.stop();
  await Promise.allSettled([hostPairing, controllerPairing, daemon].filter(Boolean).map(process => process.exited));
  await new Promise(resolve => coordinator.stop(resolve));
  await rm(directory, { recursive: true, force: true });
}
