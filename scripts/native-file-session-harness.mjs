import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createCoordinator } from '../services/coordinator/server.mjs';

const cargo = process.env.CARGO || 'cargo';
const builtAgent = process.env.WII_AGENT_BINARY || path.join(process.cwd(), 'agent', 'target', 'debug', 'wii-ultra-desk-agent');
const TEST_TURN_SECRET = 'local-harness-turn-secret-not-for-production-0123456789';

function agent(args, stateDir) {
  const invocation = existsSync(builtAgent)
    ? [builtAgent, [...args, '--state-dir', stateDir]]
    : [cargo, ['run', '--manifest-path', 'agent/Cargo.toml', '--locked', '--', ...args, '--state-dir', stateDir]];
  const child = spawn(invocation[0], invocation[1], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  let errors = '';
  const waiters = [];
  const notify = () => {
    for (const waiter of [...waiters]) {
      const match = waiter.pattern.exec(`${output}\n${errors}`);
      if (match) { clearTimeout(waiter.timer); waiters.splice(waiters.indexOf(waiter), 1); waiter.resolve(match); }
    }
  };
  child.stdout.on('data', chunk => { output += chunk.toString(); notify(); });
  child.stderr.on('data', chunk => { errors += chunk.toString(); notify(); });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolve() : reject(new Error(`agent ${args[0]} exited ${code}: ${errors}`)));
  });
  // The harness deliberately terminates children during cleanup after a
  // primary assertion failure. Keep that expected rejection from masking the
  // actionable timeout/protocol failure.
  exited.catch(() => {});
  return {
    child,
    exited,
    async wait(pattern, timeoutMs = 25_000) {
      const match = pattern.exec(`${output}\n${errors}`);
      if (match) return match;
      return new Promise((resolve, reject) => {
        const waiter = { pattern, resolve, timer: setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error(`Timed out waiting for ${pattern} from ${args[0]}:\n${output}\n${errors}`));
        }, timeoutMs) };
        waiters.push(waiter);
      });
    },
    result() {
      const line = output.trim().split('\n').findLast(value => value.startsWith('{'));
      return line ? JSON.parse(line) : undefined;
    },
    logs() { return `${output}\n${errors}`; },
    closeInput() { child.stdin.end(); },
    stop() {
      child.stdin.end();
      const timer = setTimeout(() => child.kill('SIGTERM'), 3_000);
      timer.unref();
    }
  };
}

async function runToExit(args, stateDir) {
  const process = agent(args, stateDir);
  await process.exited;
  return process.result();
}

const coordinator = createCoordinator({ turn: { sharedSecret: TEST_TURN_SECRET, urls: ['turn:127.0.0.1:9?transport=udp'] } });
await new Promise(resolve => coordinator.listen(0, '127.0.0.1', resolve));
const coordinatorUrl = `ws://127.0.0.1:${coordinator.address().port}/v1/connect`;
const directory = await mkdtemp(path.join(os.tmpdir(), 'wii-ultra-desk-native-files-'));
let host;
let controller;
let fileHost;
let fileController;

try {
  const hostDir = path.join(directory, 'host-state');
  const controllerDir = path.join(directory, 'controller-state');
  const hostRoot = path.join(directory, 'host-root');
  const controllerRoot = path.join(directory, 'controller-root');
  await Promise.all([mkdir(hostRoot), mkdir(controllerRoot)]);
  const contents = Buffer.alloc(4 * 1024 * 1024 + 123, 0x5a);
  await writeFile(path.join(controllerRoot, 'source.txt'), contents);
  await mkdir(path.join(controllerRoot, 'folder', 'nested'), { recursive: true });
  await mkdir(path.join(controllerRoot, 'folder', 'empty'));
  await writeFile(path.join(controllerRoot, 'folder', 'nested', 'leaf.txt'), 'nested authenticated file\n');

  host = agent(['pair-host', '--coordinator', coordinatorUrl, '--name', 'Local controller'], hostDir);
  const token = (await host.wait(/Pairing invitation token .*: ([A-Za-z0-9_-]{43})/))[1];
  controller = agent(['pair-controller', '--coordinator', coordinatorUrl, '--token', token, '--name', 'Local host'], controllerDir);
  const [hostSas, controllerSas] = await Promise.all([host.wait(/Pairing SAS: ([0-9-]{35})/), controller.wait(/Pairing SAS: ([0-9-]{35})/)]);
  assert.equal(hostSas[1], controllerSas[1]);
  host.child.stdin.write(`${hostSas[1]}\n`);
  controller.child.stdin.write(`${controllerSas[1]}\n`);
  await Promise.all([host.exited, controller.exited]);
  const hostPair = host.result();
  const controllerPair = controller.result();
  assert.equal(hostPair.pairing, 'trusted');
  assert.equal(controllerPair.pairing, 'trusted');
  console.log('Pairing completed; configuring scoped file roots and host grants.');

  const expiry = Date.now() + 60_000;
  await runToExit(['grant-files-read-write', '--peer-fingerprint', hostPair.peerFingerprint, '--expires-at', String(expiry)], hostDir);
  await runToExit(['configure-file-roots', '--read-root', hostRoot, '--write-root', hostRoot], hostDir);
  await runToExit(['configure-file-roots', '--read-root', controllerRoot, '--write-root', controllerRoot], controllerDir);
  console.log('Roots configured; opening native file host and controller.');

  fileHost = agent(['file-host', '--coordinator', coordinatorUrl, '--peer-locator', hostPair.peerLocator, '--peer-fingerprint', hostPair.peerFingerprint, '--bind', '127.0.0.1:0', '--local-test-skip-turn-transport'], hostDir);
  fileController = agent(['file-controller', '--coordinator', coordinatorUrl, '--peer-locator', controllerPair.peerLocator, '--peer-fingerprint', controllerPair.peerFingerprint, '--bind', '127.0.0.1:0', '--local-test-skip-turn-transport'], controllerDir);
  await fileController.wait(/"type":"capabilities","read":true,"write":true/);
  console.log('File channel open with separately reported read/write authorization.');
  fileController.child.stdin.write('{"type":"list_local","path":"0/."}\n');
  await fileController.wait(/"type":"entries","pane":"local".*"source\.txt"/);
  fileController.child.stdin.write('{"type":"upload","transfer_id":"abcdefghijklmnopqrstuv","source":"0/source.txt","destination":"0/uploaded.txt","collision":"fail"}\n');
  await fileController.wait(/"type":"transfer","transfer_id":"abcdefghijklmnopqrstuv".*"status":"complete"/);
  console.log('Upload completed; verifying atomic destination bytes.');
  assert.deepEqual(await readFile(path.join(hostRoot, 'uploaded.txt')), contents, 'upload must atomically deliver identical bytes');

  fileController.child.stdin.write('{"type":"download","transfer_id":"zyxwvutsrqponmlkjihgfe","source":"0/uploaded.txt","destination":"0/downloaded.txt","collision":"fail"}\n');
  await fileController.wait(/"type":"transfer","transfer_id":"zyxwvutsrqponmlkjihgfe".*"status":"complete"/);
  console.log('Download completed; verifying returned bytes.');
  assert.deepEqual(await readFile(path.join(controllerRoot, 'downloaded.txt')), contents, 'download must atomically deliver identical bytes');
  fileController.child.stdin.write('{"type":"upload","transfer_id":"1111111111111111111111","source":"0/folder","destination":"0/folder-copy","collision":"fail"}\n');
  await fileController.wait(/"type":"transfer","transfer_id":"1111111111111111111111".*"status":"complete"/);
  assert.equal(await readFile(path.join(hostRoot, 'folder-copy', 'nested', 'leaf.txt'), 'utf8'), 'nested authenticated file\n');
  assert.equal((await stat(path.join(hostRoot, 'folder-copy', 'empty'))).isDirectory(), true, 'empty directories are represented by a safe directory create operation');
  fileController.child.stdin.write('{"type":"download","transfer_id":"2222222222222222222222","source":"0/folder-copy","destination":"0/folder-roundtrip","collision":"fail"}\n');
  await fileController.wait(/"type":"transfer","transfer_id":"2222222222222222222222".*"status":"complete"/);
  assert.equal(await readFile(path.join(controllerRoot, 'folder-roundtrip', 'nested', 'leaf.txt'), 'utf8'), 'nested authenticated file\n');
  assert.equal((await stat(path.join(controllerRoot, 'folder-roundtrip', 'empty'))).isDirectory(), true, 'empty directories round trip safely');
  fileController.child.stdin.write('{"type":"disconnect"}\n');
  fileHost.child.stdin.write('{"type":"disconnect"}\n');
  fileController.closeInput();
  fileHost.closeInput();
  await Promise.all([fileController.exited, fileHost.exited]);
  console.log('Two paired native agents completed direct authenticated file upload and download over a real WebRTC data channel.');
  console.log('The unreachable TURN URL proves no relay allocation; do not cite this as relay evidence.');
} finally {
  for (const process of [host, controller, fileHost, fileController]) process?.stop();
  await Promise.allSettled([host, controller, fileHost, fileController].filter(Boolean).map(process => process.exited));
  await new Promise(resolve => coordinator.stop(resolve));
  await rm(directory, { recursive: true, force: true });
}
