const { app, BrowserWindow, ipcMain, session, protocol, net } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs/promises');
const { spawn } = require('node:child_process');
const { validateBookmark } = require('./validation.cjs');

protocol.registerSchemesAsPrivileged([{ scheme: 'wiidesk', privileges: {
  standard: true, secure: true, supportFetchAPI: true
} }]);
let mainWindow;
let writeQueue = Promise.resolve();
let desktopSession;
let sshSession;
let fileSession;
const allowedFiles = new Map([
  ['/index.html', 'index.html'], ['/renderer.bundle.js', 'renderer.bundle.js'], ['/styles.css', 'styles.css'], ['/xterm.css', 'xterm.css']
]);
const pageUrl = 'wiidesk://app/index.html';
const bookmarkFile = () => path.join(app.getPath('userData'), 'bookmarks.json');
function agentArguments(args) {
  const output = [];
  if (process.env.WII_AGENT_STATE_DIR) output.push('--state-dir', process.env.WII_AGENT_STATE_DIR);
  return [...args, ...output];
}

function agentControl(action) {
  if (!['status', 'disconnect', 'disable'].includes(action)) throw new Error('Invalid local agent control action');
  return new Promise((resolve, reject) => {
    const child = spawn(agentBinary(), agentArguments(['local-control', '--action', action]), { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    const limit = 16_384;
    const timer = setTimeout(() => child.kill('SIGTERM'), 6_000);
    timer.unref();
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', value => { stdout += value; if (stdout.length > limit) child.kill('SIGTERM'); });
    child.stderr.on('data', value => { stderr += value; if (stderr.length > 1_024) stderr = stderr.slice(0, 1_024); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error('Local agent service is unavailable. Start the per-user native agent service before using unattended controls.'));
      try {
        const value = JSON.parse(stdout.trim());
        if (!value || typeof value !== 'object' || value.ok !== true || value.code !== 'ok' || !value.status || typeof value.status.enabled !== 'boolean' || !Array.isArray(value.status.allowedCapabilities) || !Number.isSafeInteger(value.status.activeSessions)) throw new Error('Invalid local agent response');
        resolve(Object.freeze(value));
      } catch {
        reject(new Error('Local agent service returned an invalid response.'));
      }
    });
  });
}

async function agentStatus() {
  try {
    const value = await agentControl('status');
    return Object.freeze({
      agent: 'connected', identity: 'protected_native_store', pairing: 'native_managed', trustedDevices: 0,
      unattendedEnabled: value.status.enabled, unattendedScopes: [...value.status.allowedCapabilities],
      activeUnattendedSessions: value.status.activeSessions, connectionState: 'local_authenticated', route: 'local_ipc',
      diagnostic: value.status.enabled ? 'Unattended access is enabled only for the listed scopes.' : 'Unattended access is off. Paired devices and bookmarks cannot bypass this state.'
    });
  } catch {
    return Object.freeze({
      agent: 'not_connected', identity: 'unavailable', pairing: 'unavailable', trustedDevices: 0,
      unattendedEnabled: false, unattendedScopes: [], activeUnattendedSessions: 0,
      connectionState: 'unavailable', route: 'not_connected',
      diagnostic: 'Local agent IPC is not running; unattended controls and background sessions are unavailable.'
    });
  }
}

async function unattendedControl(action) {
  if (action === 'disconnect' || action === 'disable') {
    stopDesktopSession('local_unattended_control');
    stopManagedSession('ssh', 'local_unattended_control');
    stopManagedSession('file', 'local_unattended_control');
  }
  const value = await agentControl(action);
  return Object.freeze({
    agent: 'connected', identity: 'protected_native_store', pairing: 'native_managed', trustedDevices: 0,
    unattendedEnabled: value.status.enabled, unattendedScopes: [...value.status.allowedCapabilities],
    activeUnattendedSessions: value.status.activeSessions, connectionState: 'local_authenticated', route: 'local_ipc',
    diagnostic: value.status.enabled ? 'Unattended access remains enabled with current scoped grants.' : 'Unattended access is disabled; affected native channels are terminated.'
  });
}

function requireString(value, description, pattern, minimum = 1, maximum = 512) {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || (pattern && !pattern.test(value))) {
    throw new Error(`Invalid ${description}`);
  }
  return value;
}

function validatedCoordinator(value) {
  const url = new URL(requireString(value, 'coordinator URL', undefined, 1, 512));
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(url.hostname);
  if ((url.protocol !== 'wss:' && !(url.protocol === 'ws:' && loopback)) || url.pathname !== '/v1/connect' || url.username || url.password || url.search || url.hash) {
    throw new Error('Coordinator must be a wss:// URL ending in /v1/connect; ws:// is loopback development only');
  }
  return url.toString();
}

function validatedDesktopConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid desktop session request');
  const keys = Object.keys(value).sort();
  const expected = ['bindAddress', 'controlRequested', 'coordinator', 'iceMode', 'monitorId', 'peerFingerprint', 'peerLocator', 'quality', 'role', 'stunUrls'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new Error('Invalid desktop session fields');
  const role = requireString(value.role, 'desktop role', /^(controller|host)$/);
  const peerLocator = requireString(value.peerLocator, 'peer locator', /^[A-Za-z0-9_-]{22}$/, 22, 22);
  const peerFingerprint = requireString(value.peerFingerprint, 'peer fingerprint', /^[a-f0-9]{64}$/, 64, 64);
  const iceMode = requireString(value.iceMode, 'ICE mode', /^(automatic|relay-only)$/);
  const quality = requireString(value.quality, 'quality mode', /^(auto|clear-text|smooth-motion|low-bandwidth)$/);
  if (typeof value.controlRequested !== 'boolean') throw new Error('Invalid control request');
  if (value.monitorId !== null && (!Number.isInteger(value.monitorId) || value.monitorId < 0 || value.monitorId > 0xffffffff)) throw new Error('Invalid monitor ID');
  if (!Array.isArray(value.stunUrls) || value.stunUrls.length > 4 || value.stunUrls.some(url => typeof url !== 'string' || url.length > 256 || !/^stuns?:[^\s]+$/i.test(url))) throw new Error('Invalid STUN URLs');
  const bindAddress = requireString(value.bindAddress, 'bind address', /^[A-Za-z0-9.:[\]-]{3,128}$/);
  return Object.freeze({ role, coordinator: validatedCoordinator(value.coordinator), peerLocator, peerFingerprint, iceMode, quality,
    controlRequested: value.controlRequested, monitorId: value.monitorId, stunUrls: [...value.stunUrls], bindAddress });
}

function validatedDesktopInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid desktop input');
  const inputType = value.type;
  if (inputType === 'pointer' && Number.isFinite(value.x) && Number.isFinite(value.y) && value.x >= 0 && value.x <= 1 && value.y >= 0 && value.y <= 1 && Object.keys(value).length === 3) return { type: 'input', input: { kind: 'pointer', x: value.x, y: value.y } };
  if (inputType === 'button' && /^(left|middle|right)$/.test(value.button) && typeof value.pressed === 'boolean' && Object.keys(value).length === 3) return { type: 'input', input: { kind: 'button', button: value.button, pressed: value.pressed } };
  if (inputType === 'scroll' && Number.isInteger(value.horizontal) && Number.isInteger(value.vertical) && Math.abs(value.horizontal) <= 1000 && Math.abs(value.vertical) <= 1000 && typeof value.smooth === 'boolean' && Object.keys(value).length === 4) return { type: 'input', input: { kind: 'scroll', horizontal: value.horizontal, vertical: value.vertical, smooth: value.smooth } };
  if (inputType === 'key' && /^(alt|backspace|control|delete|down|end|enter|escape|home|left|meta|page_down|page_up|right|shift|tab|up)$/.test(value.key) && typeof value.pressed === 'boolean' && Object.keys(value).length === 3) return { type: 'input', input: { kind: 'key', key: value.key, pressed: value.pressed } };
  if (inputType === 'text' && typeof value.text === 'string' && value.text.length > 0 && value.text.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value.text) && Object.keys(value).length === 2) return { type: 'input', input: { kind: 'text', text: value.text } };
  if (inputType === 'release_all' && Object.keys(value).length === 1) return { type: 'input', input: { kind: 'release_all' } };
  throw new Error('Invalid desktop input');
}

function agentBinary() {
  const binary = process.env.WII_AGENT_BINARY;
  if (binary && path.isAbsolute(binary)) return binary;
  if (app.isPackaged) return path.join(process.resourcesPath, 'agent', process.platform === 'win32' ? 'wii-ultra-desk-agent.exe' : 'wii-ultra-desk-agent');
  throw new Error('Native agent is not configured. Set WII_AGENT_BINARY to an absolute agent path.');
}

function desktopStatus() {
  if (!desktopSession) return Object.freeze({ active: false, diagnostic: 'No desktop session is running.' });
  return Object.freeze({ active: true, role: desktopSession.config.role, startedAt: desktopSession.startedAt, diagnostic: 'Native agent session is active.' });
}

function safeDesktopEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.type !== 'string') return undefined;
  if (value.type === 'state' && (!/^(connecting|connected|closed|failed)$/.test(value.state) || !/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128)) return undefined;
  if (value.type === 'failure' && (typeof value.code !== 'string' || !/^(authorization_denied|control_denied|capability_unavailable|timeout|transport_failed|coordinator_denied|protocol_rejected|native_session_failed)$/.test(value.code))) return undefined;
  if (value.type === 'control' && typeof value.allowed !== 'boolean') return undefined;
  if (value.type === 'host_indicator' && (typeof value.active !== 'boolean' || (value.monitor_id !== null && (!Number.isSafeInteger(value.monitor_id) || value.monitor_id < 0)))) return undefined;
  if (value.type === 'monitor' && (!value.monitor || typeof value.monitor !== 'object' || !Number.isSafeInteger(value.monitor.id) || !Number.isSafeInteger(value.monitor.width) || !Number.isSafeInteger(value.monitor.height) || value.monitor.width < 1 || value.monitor.height < 1 || typeof value.monitor.name !== 'string' || value.monitor.name.length > 160 || typeof value.keyboard_layout !== 'string' || value.keyboard_layout.length > 80)) return undefined;
  if (value.type === 'stats' && (!Number.isSafeInteger(value.captured_frames) || !Number.isSafeInteger(value.sent_frames) || !Number.isSafeInteger(value.dropped_frames) || !Number.isSafeInteger(value.encode_ms) || typeof value.hardware_encoder_verified !== 'boolean')) return undefined;
  if (value.type === 'closed' && (!/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128 || typeof value.reauthenticated !== 'boolean' || !Number.isSafeInteger(value.attempts) || value.attempts < 0 || value.attempts > 5)) return undefined;
  if (value.type === 'frame') {
    if (!Number.isSafeInteger(value.sequence) || !Number.isSafeInteger(value.width) || !Number.isSafeInteger(value.height) || value.width < 1 || value.height < 1 || value.width > 4096 || value.height > 4096 || typeof value.jpeg !== 'string' || !/^[A-Za-z0-9+/]*$/.test(value.jpeg) || value.jpeg.length > 70_000) return undefined;
  }
  if (!['state', 'failure', 'control', 'host_indicator', 'monitor', 'frame', 'stats', 'closed'].includes(value.type)) return undefined;
  return value;
}

function forwardDesktopEvent(value) {
  const event = safeDesktopEvent(value);
  if (event && mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('desktop:event', event);
}

function stopDesktopSession(reason = 'local_disconnect') {
  const active = desktopSession;
  if (!active) return false;
  desktopSession = undefined;
  try { active.child.stdin.write(`${JSON.stringify({ type: 'disconnect', reason })}\n`); } catch {}
  const timer = setTimeout(() => { if (!active.child.killed) active.child.kill('SIGTERM'); }, 5_000);
  timer.unref();
  forwardDesktopEvent({ type: 'closed', route: 'unknown', session_id: '', reauthenticated: false, attempts: 0 });
  return true;
}

function startDesktopSession(request) {
  if (desktopSession) throw new Error('A desktop session is already active');
  const config = validatedDesktopConfig(request);
  const command = config.role === 'controller' ? 'desktop-controller' : 'desktop-host';
  const args = [command, '--coordinator', config.coordinator, '--peer-locator', config.peerLocator, '--peer-fingerprint', config.peerFingerprint,
    '--ice-mode', config.iceMode, '--quality', config.quality, '--bind', config.bindAddress];
  if (config.monitorId !== null) args.push('--monitor', String(config.monitorId));
  if (config.controlRequested) args.push('--request-control');
  for (const stun of config.stunUrls) args.push('--stun', stun);
  if (process.env.WII_AGENT_STATE_DIR) args.push('--state-dir', process.env.WII_AGENT_STATE_DIR);
  const child = spawn(agentBinary(), args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const active = { child, config, startedAt: Date.now(), stdout: '' };
  desktopSession = active;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    active.stdout = `${active.stdout}${chunk}`;
    if (active.stdout.length > 180_000) { stopDesktopSession('agent_output_limit'); return; }
    let newline;
    while ((newline = active.stdout.indexOf('\n')) >= 0) {
      const line = active.stdout.slice(0, newline); active.stdout = active.stdout.slice(newline + 1);
      if (line.length > 90_000) { stopDesktopSession('agent_event_limit'); return; }
      try {
        const event = safeDesktopEvent(JSON.parse(line));
        if (event?.type === 'failure') active.failed = true;
        if (event) forwardDesktopEvent(event);
      } catch { /* Native diagnostics may be non-JSON; never forward them. */ }
    }
  });
  child.once('error', () => { if (desktopSession === active) desktopSession = undefined; if (!active.failed) forwardDesktopEvent({ type: 'closed', route: 'unknown', session_id: '', reauthenticated: false, attempts: 0 }); });
  child.once('exit', () => { if (desktopSession === active) desktopSession = undefined; if (!active.failed) forwardDesktopEvent({ type: 'closed', route: 'unknown', session_id: '', reauthenticated: false, attempts: 0 }); });
  return desktopStatus();
}

function validatedTransferConfig(value, feature) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Invalid ${feature} session request`);
  const keys = Object.keys(value).sort();
  const expected = ['bindAddress', 'coordinator', 'iceMode', 'peerFingerprint', 'peerLocator', 'role', 'stunUrls'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new Error(`Invalid ${feature} session fields`);
  const role = requireString(value.role, `${feature} role`, /^(controller|host)$/);
  const peerLocator = requireString(value.peerLocator, 'peer locator', /^[A-Za-z0-9_-]{22}$/, 22, 22);
  const peerFingerprint = requireString(value.peerFingerprint, 'peer fingerprint', /^[a-f0-9]{64}$/, 64, 64);
  const iceMode = requireString(value.iceMode, 'ICE mode', /^(automatic|relay-only)$/);
  if (!Array.isArray(value.stunUrls) || value.stunUrls.length > 4 || value.stunUrls.some(url => typeof url !== 'string' || url.length > 256 || !/^stuns?:[^\s]+$/i.test(url))) throw new Error('Invalid STUN URLs');
  return Object.freeze({ role, coordinator: validatedCoordinator(value.coordinator), peerLocator, peerFingerprint, iceMode,
    stunUrls: [...value.stunUrls], bindAddress: requireString(value.bindAddress, 'bind address', /^[A-Za-z0-9.:[\]-]{3,128}$/) });
}

function validatedSshConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid SSH session request');
  const keys = Object.keys(value).sort();
  const expected = ['bindAddress', 'coordinator', 'iceMode', 'peerFingerprint', 'peerLocator', 'role', 'stunUrls', 'username'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new Error('Invalid SSH session fields');
  const config = validatedTransferConfig(Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'username')), 'SSH');
  return Object.freeze({ ...config, username: requireString(value.username, 'SSH username', /^[A-Za-z0-9._-]{1,64}$/) });
}

function safeSshEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.type !== 'string') return undefined;
  if (value.type === 'state' && (!/^(connecting|connected|closed|failed)$/.test(value.state) || !/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128)) return undefined;
  if (value.type === 'terminal' && (typeof value.data !== 'string' || value.data.length < 1 || value.data.length > 22_000 || !/^[A-Za-z0-9+/]+$/.test(value.data))) return undefined;
  if (value.type === 'host_key' && !/^(approval_required|changed_key_rejected)$/.test(value.state)) return undefined;
  if (value.type === 'failure' && !/^(authorization_denied|ssh_unavailable|timeout|transport_failed|coordinator_denied|protocol_rejected|native_session_failed)$/.test(value.code)) return undefined;
  if (value.type === 'closed' && (!/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128 || typeof value.reauthenticated !== 'boolean' || !Number.isSafeInteger(value.attempts) || value.attempts < 0 || value.attempts > 5)) return undefined;
  return ['state', 'terminal', 'host_key', 'failure', 'closed'].includes(value.type) ? value : undefined;
}

function filePath(value, description) {
  return requireString(value, description, /^[^\0\\]{1,1024}$/);
}

function safeFileEntry(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 255 && !/[\0-\x1f<>:"\\|?*]/.test(value.name) && typeof value.path === 'string' && value.path.length > 0 && value.path.length <= 1024 && /^(file|directory)$/.test(value.kind) && Number.isSafeInteger(value.size) && value.size >= 0;
}

function safeFileEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.type !== 'string') return undefined;
  if (value.type === 'state' && (!/^(connecting|connected|closed|failed)$/.test(value.state) || !/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128)) return undefined;
  if (value.type === 'capabilities' && (typeof value.read !== 'boolean' || typeof value.write !== 'boolean')) return undefined;
  if (value.type === 'entries' && (!/^(local|remote)$/.test(value.pane) || typeof value.path !== 'string' || value.path.length > 1024 || !Array.isArray(value.entries) || value.entries.length > 256 || value.entries.some(entry => !safeFileEntry(entry)))) return undefined;
  if (value.type === 'transfer' && (!/^[A-Za-z0-9_-]{22}$/.test(value.transfer_id) || !/^(upload|download)$/.test(value.direction) || typeof value.path !== 'string' || value.path.length > 1024 || !Number.isSafeInteger(value.transferred) || !Number.isSafeInteger(value.total) || value.transferred < 0 || value.total < value.transferred || !/^(running|complete)$/.test(value.status))) return undefined;
  if (value.type === 'failure' && !/^(authorization_denied|file_operation_rejected|timeout|transport_failed|coordinator_denied|protocol_rejected|native_session_failed)$/.test(value.code)) return undefined;
  if (value.type === 'closed' && (!/^(host_direct|server_reflexive_direct|relayed|unknown)$/.test(value.route) || typeof value.session_id !== 'string' || value.session_id.length > 128 || typeof value.reauthenticated !== 'boolean' || !Number.isSafeInteger(value.attempts) || value.attempts < 0 || value.attempts > 5)) return undefined;
  return ['state', 'capabilities', 'entries', 'transfer', 'failure', 'closed'].includes(value.type) ? value : undefined;
}

function forwardManagedEvent(channel, guard, value) {
  const event = guard(value);
  if (event && mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, event);
}

function sessionStatus(active, noun) {
  return active ? Object.freeze({ active: true, role: active.config.role, startedAt: active.startedAt, diagnostic: `Native ${noun} session is active.` }) : Object.freeze({ active: false, diagnostic: `No ${noun} session is running.` });
}

function stopManagedSession(kind, reason = 'local_disconnect') {
  const active = kind === 'ssh' ? sshSession : fileSession;
  if (!active) return false;
  if (kind === 'ssh') sshSession = undefined; else fileSession = undefined;
  try { active.child.stdin.write(`${JSON.stringify({ type: 'disconnect', reason })}\n`); } catch {}
  const timer = setTimeout(() => { if (!active.child.killed) active.child.kill('SIGTERM'); }, 5_000);
  timer.unref();
  return true;
}

function startManagedSession(kind, request) {
  const ssh = kind === 'ssh';
  if (ssh ? sshSession : fileSession) throw new Error(`A ${ssh ? 'SSH' : 'file'} session is already active`);
  const config = ssh ? validatedSshConfig(request) : validatedTransferConfig(request, 'file');
  const command = `${kind}-${config.role}`;
  const args = [command, '--coordinator', config.coordinator, '--peer-locator', config.peerLocator, '--peer-fingerprint', config.peerFingerprint, '--ice-mode', config.iceMode, '--bind', config.bindAddress];
  if (ssh) args.push('--username', config.username);
  for (const stun of config.stunUrls) args.push('--stun', stun);
  if (process.env.WII_AGENT_STATE_DIR) args.push('--state-dir', process.env.WII_AGENT_STATE_DIR);
  const child = spawn(agentBinary(), args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const active = { child, config, startedAt: Date.now(), stdout: '', failed: false };
  if (ssh) sshSession = active; else fileSession = active;
  const guard = ssh ? safeSshEvent : safeFileEvent;
  const eventChannel = ssh ? 'ssh:event' : 'file:event';
  const outputLimit = ssh ? 96_000 : 180_000;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    active.stdout = `${active.stdout}${chunk}`;
    if (active.stdout.length > outputLimit) { stopManagedSession(kind, 'agent_output_limit'); return; }
    let newline;
    while ((newline = active.stdout.indexOf('\n')) >= 0) {
      const line = active.stdout.slice(0, newline); active.stdout = active.stdout.slice(newline + 1);
      if (line.length > outputLimit) { stopManagedSession(kind, 'agent_event_limit'); return; }
      try {
        const event = guard(JSON.parse(line));
        if (event?.type === 'failure') active.failed = true;
        if (event) forwardManagedEvent(eventChannel, guard, event);
      } catch { /* Native diagnostics are never forwarded to an untrusted renderer. */ }
    }
  });
  const close = () => {
    if ((ssh ? sshSession : fileSession) === active) {
      if (ssh) sshSession = undefined; else fileSession = undefined;
      if (!active.failed) forwardManagedEvent(eventChannel, guard, { type: 'closed', route: 'unknown', session_id: '', reauthenticated: false, attempts: 0 });
    }
  };
  child.once('error', close);
  child.once('exit', close);
  return sessionStatus(active, ssh ? 'SSH' : 'file');
}

function canonicalBase64(value, description, maximumBytes) {
  if (typeof value !== 'string' || value.length < 1 || value.length > Math.ceil(maximumBytes * 4 / 3) || !/^[A-Za-z0-9+/]+$/.test(value)) throw new Error(`Invalid ${description}`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < 1 || bytes.length > maximumBytes || bytes.toString('base64').replace(/=+$/, '') !== value) throw new Error(`Invalid ${description}`);
  return value;
}

function validatedSshCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid SSH terminal command');
  if (value.type === 'input' && Object.keys(value).length === 2) return { type: 'input', data: canonicalBase64(value.data, 'terminal input', 16_384) };
  if (value.type === 'resize' && Object.keys(value).length === 3 && Number.isInteger(value.cols) && Number.isInteger(value.rows) && value.cols >= 1 && value.cols <= 500 && value.rows >= 1 && value.rows <= 300) return { type: 'resize', cols: value.cols, rows: value.rows };
  throw new Error('Invalid SSH terminal command');
}

function validatedFileCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid file command');
  if ((value.type === 'list_local' || value.type === 'list_remote') && Object.keys(value).length === 2) return { type: value.type, path: filePath(value.path, 'file path') };
  if ((value.type === 'upload' || value.type === 'download') && Object.keys(value).length === 5 && /^[A-Za-z0-9_-]{22}$/.test(value.transfer_id) && /^(fail|replace)$/.test(value.collision)) return { type: value.type, transfer_id: value.transfer_id, source: filePath(value.source, 'source path'), destination: filePath(value.destination, 'destination path'), collision: value.collision };
  if (value.type === 'cancel' && Object.keys(value).length === 2 && /^[A-Za-z0-9_-]{22}$/.test(value.transfer_id)) return { type: 'cancel', transfer_id: value.transfer_id };
  throw new Error('Invalid file command');
}
async function readBookmarks() {
  try {
    const data = JSON.parse(await fs.readFile(bookmarkFile(), 'utf8'));
    if (!Array.isArray(data) || data.length > 128) throw new Error('Invalid bookmarks file');
    return data.map(validateBookmark);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}
function trustedSender(event) {
  return mainWindow && event.sender === mainWindow.webContents &&
    event.senderFrame === mainWindow.webContents.mainFrame && event.senderFrame.url === pageUrl;
}
function handler(channel, fn) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!trustedSender(event)) throw new Error('Untrusted IPC sender');
    return fn(...args);
  });
}
function createWindow() {
  mainWindow = new BrowserWindow({ width: 1100, height: 780, minWidth: 800, minHeight: 650,
    backgroundColor: '#101827', webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true,
      nodeIntegration: false, sandbox: true, webSecurity: true
    }
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', event => event.preventDefault());
  mainWindow.loadURL(pageUrl);
}
app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  protocol.handle('wiidesk', request => {
    const url = new URL(request.url);
    const asset = url.hostname === 'app' && allowedFiles.get(url.pathname);
    if (request.method !== 'GET' || !asset || url.search) return new Response('Not found', { status: 404 });
    return net.fetch(pathToFileURL(path.join(__dirname, 'ui', asset)).href);
  });
  handler('bookmarks:list', readBookmarks);
  handler('agent:status', agentStatus);
  handler('unattended:disconnect', () => unattendedControl('disconnect'));
  handler('unattended:disable', () => unattendedControl('disable'));
  handler('desktop:status', desktopStatus);
  handler('desktop:start', startDesktopSession);
  handler('desktop:stop', () => ({ stopped: stopDesktopSession() }));
  handler('desktop:input', value => {
    if (!desktopSession || desktopSession.config.role !== 'controller') throw new Error('No controller desktop session is active');
    const command = validatedDesktopInput(value);
    const line = JSON.stringify(command);
    if (line.length > 2_048 || !desktopSession.child.stdin.write(`${line}\n`)) throw new Error('Native desktop input queue is full');
    return { accepted: true };
  });
  handler('ssh:status', () => sessionStatus(sshSession, 'SSH'));
  handler('ssh:start', value => startManagedSession('ssh', value));
  handler('ssh:stop', () => ({ stopped: stopManagedSession('ssh') }));
  handler('ssh:command', value => {
    if (!sshSession || sshSession.config.role !== 'controller') throw new Error('No controller SSH session is active');
    const command = validatedSshCommand(value);
    const line = JSON.stringify(command);
    if (line.length > 24_000 || !sshSession.child.stdin.write(`${line}\n`)) throw new Error('Native SSH input queue is full');
    return { accepted: true };
  });
  handler('file:status', () => sessionStatus(fileSession, 'file'));
  handler('file:start', value => startManagedSession('file', value));
  handler('file:stop', () => ({ stopped: stopManagedSession('file') }));
  handler('file:command', value => {
    if (!fileSession || fileSession.config.role !== 'controller') throw new Error('No controller file session is active');
    const command = validatedFileCommand(value);
    const line = JSON.stringify(command);
    if (line.length > 4_096 || !fileSession.child.stdin.write(`${line}\n`)) throw new Error('Native file command queue is full');
    return { accepted: true };
  });
  handler('bookmarks:save', value => {
    const bookmark = validateBookmark(value);
    // Serialize read/modify/write operations, preserving concurrent saves.
    const operation = writeQueue.then(async () => {
      const bookmarks = await readBookmarks();
      const index = bookmarks.findIndex(x => x.deviceId === bookmark.deviceId);
      if (index < 0) {
        if (bookmarks.length >= 128) throw new Error('Bookmark limit reached');
        bookmarks.push(bookmark);
      } else bookmarks[index] = bookmark;
      await fs.mkdir(app.getPath('userData'), { recursive: true });
      const temp = `${bookmarkFile()}.tmp`;
      await fs.writeFile(temp, JSON.stringify(bookmarks, null, 2), { mode: 0o600 });
      await fs.rename(temp, bookmarkFile());
      return bookmarks;
    });
    writeQueue = operation.catch(() => {});
    return operation;
  });
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('before-quit', () => { stopDesktopSession('electron_quit'); stopManagedSession('ssh', 'electron_quit'); stopManagedSession('file', 'electron_quit'); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
