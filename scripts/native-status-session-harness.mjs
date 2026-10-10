import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createCoordinator } from '../services/coordinator/server.mjs';

const cargo = process.env.CARGO || 'cargo';
const TEST_TURN_SECRET = 'local-harness-turn-secret-not-for-production-0123456789';

function agent(args, stateDir) {
  const child = spawn(cargo, [
    'run', '--manifest-path', 'agent/Cargo.toml', '--locked', '--',
    ...args, '--state-dir', stateDir
  ], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  let errors = '';
  const waiters = [];
  const notify = () => {
    for (const waiter of [...waiters]) {
      const match = waiter.pattern.exec(`${output}\n${errors}`);
      if (match) {
        clearTimeout(waiter.timer);
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve(match);
      }
    }
  };
  child.stdout.on('data', chunk => { output += chunk.toString(); notify(); });
  child.stderr.on('data', chunk => { errors += chunk.toString(); notify(); });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => {
      if (code === 0) resolve();
      else reject(new Error(`agent ${args[0]} exited ${code}: ${errors}`));
    });
  });
  return {
    child,
    exited,
    async wait(pattern, timeoutMs = 20_000) {
      const match = pattern.exec(`${output}\n${errors}`);
      if (match) return match;
      return new Promise((resolve, reject) => {
        const waiter = { pattern, resolve, timer: setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error(`Timed out waiting for ${pattern} from ${args[0]}: ${output}\n${errors}`));
        }, timeoutMs) };
        waiters.push(waiter);
      });
    },
    result() {
      const line = output.trim().split('\n').findLast(value => value.startsWith('{'));
      return line ? JSON.parse(line) : undefined;
    },
    logs() { return `${output}\n${errors}`; },
    stop() { child.kill('SIGTERM'); }
  };
}

async function runToExit(args, stateDir) {
  const process = agent(args, stateDir);
  await process.exited;
  return process.result();
}

const coordinator = createCoordinator({
  turn: {
    sharedSecret: TEST_TURN_SECRET,
    // Deliberately unreachable: the test proves direct host ICE after real
    // coordinator-issued credentials, not a relay allocation.
    urls: ['turn:127.0.0.1:9?transport=udp']
  }
});
await new Promise(resolve => coordinator.listen(0, '127.0.0.1', resolve));
const coordinatorUrl = `ws://127.0.0.1:${coordinator.address().port}/v1/connect`;
const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-desk-native-status-'));
let host;
let controller;
let listener;
let initiator;

try {
  const hostDir = path.join(directory, 'host');
  const controllerDir = path.join(directory, 'controller');
  host = agent(['pair-host', '--coordinator', coordinatorUrl, '--name', 'Local controller'], hostDir);
  const token = (await host.wait(/Pairing invitation token .*: ([A-Za-z0-9_-]{43})/))[1];
  controller = agent(['pair-controller', '--coordinator', coordinatorUrl, '--token', token, '--name', 'Local host'], controllerDir);
  const [hostSas, controllerSas] = await Promise.all([
    host.wait(/Pairing SAS: ([0-9-]{35})/),
    controller.wait(/Pairing SAS: ([0-9-]{35})/)
  ]);
  assert.equal(hostSas[1], controllerSas[1], 'both native agents must derive the same attended SAS');
  host.child.stdin.write(`${hostSas[1]}\n`);
  controller.child.stdin.write(`${controllerSas[1]}\n`);
  await Promise.all([host.exited, controller.exited]);
  const hostPair = host.result();
  const controllerPair = controller.result();
  assert.equal(hostPair.pairing, 'trusted');
  assert.equal(controllerPair.pairing, 'trusted');

  const expiry = Date.now() + 60_000;
  // The responder is the host authorization boundary.  The initiating
  // controller verifies the host's pinned identity but must not need to grant
  // the host reverse desktop access merely to open this status transport.
  await runToExit(['grant-desktop-view', '--peer-fingerprint', hostPair.peerFingerprint, '--expires-at', String(expiry)], hostDir);

  listener = agent([
    'status-listen', '--coordinator', coordinatorUrl,
    '--peer-locator', hostPair.peerLocator, '--peer-fingerprint', hostPair.peerFingerprint,
    '--bind', '127.0.0.1:0', '--local-test-skip-turn-transport'
  ], hostDir);
  await listener.wait(/status-session state=signaling role=responder attempt=1/);
  initiator = agent([
    'status-initiate', '--coordinator', coordinatorUrl,
    '--peer-locator', controllerPair.peerLocator, '--peer-fingerprint', controllerPair.peerFingerprint,
    '--bind', '127.0.0.1:0', '--local-test-skip-turn-transport'
  ], controllerDir);
  const completed = await Promise.allSettled([listener.exited, initiator.exited]);
  if (completed.some(result => result.status === 'rejected')) {
    throw new Error(`native status session failed\nlistener:\n${listener.logs()}\ninitiator:\n${initiator.logs()}`);
  }
  const listenerResult = listener.result();
  const initiatorResult = initiator.result();
  assert.equal(listenerResult.pingCompleted, true);
  assert.equal(initiatorResult.pingCompleted, true);
  assert.equal(listenerResult.route, 'host_direct');
  assert.equal(initiatorResult.route, 'host_direct');
  assert.equal(listenerResult.attempts, 1);
  assert.equal(initiatorResult.attempts, 1);
  console.log('Two native agents completed attended pairing, a host-only fresh view grant, coordinator signaling, and a real host/direct WebRTC ping/pong.');
  console.log('The unreachable TURN URL proves no relay allocation; do not cite this as relay fallback evidence.');
} finally {
  for (const process of [host, controller, listener, initiator]) process?.stop();
  await new Promise(resolve => coordinator.stop(resolve));
  await rm(directory, { recursive: true, force: true });
}
