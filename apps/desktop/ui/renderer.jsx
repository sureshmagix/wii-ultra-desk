import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

const namedKeys = Object.freeze({
  Alt: 'alt', Backspace: 'backspace', Control: 'control', Delete: 'delete', ArrowDown: 'down',
  End: 'end', Enter: 'enter', Escape: 'escape', Home: 'home', ArrowLeft: 'left', Meta: 'meta',
  PageDown: 'page_down', PageUp: 'page_up', ArrowRight: 'right', Shift: 'shift', Tab: 'tab', ArrowUp: 'up'
});
const qualityLabels = Object.freeze({ auto: 'Auto', 'clear-text': 'Clear text', 'smooth-motion': 'Smooth motion', 'low-bandwidth': 'Low bandwidth' });
const routeLabel = route => ({ host_direct: 'Host/direct', server_reflexive_direct: 'Server-reflexive/direct', relayed: 'Relayed' }[route] ?? 'Negotiating');
const transferId = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
};
const textToBase64 = value => {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/, '');
};
const base64ToBytes = value => {
  const padded = `${value}${'='.repeat((4 - value.length % 4) % 4)}`;
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
};

function Status({ label, value }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function App() {
  const [bookmarks, setBookmarks] = useState([]);
  const [notice, setNotice] = useState('Bookmarks are locators only. Verify an identity and grant access on the host before connecting.');
  const [agent, setAgent] = useState(null);
  const [config, setConfig] = useState({
    role: 'controller', coordinator: '', peerLocator: '', peerFingerprint: '', bindAddress: '0.0.0.0:0',
    iceMode: 'automatic', quality: 'auto', monitorId: '', stunUrls: '', controlRequested: false
  });
  const [desktop, setDesktop] = useState({ active: false, state: 'idle', route: 'unknown', control: false, monitor: null, stats: null, frame: null, hostActive: false });
  const [sshConfig, setSshConfig] = useState({ role: 'controller', coordinator: '', peerLocator: '', peerFingerprint: '', bindAddress: '0.0.0.0:0', iceMode: 'automatic', stunUrls: '', username: '' });
  const [ssh, setSsh] = useState({ active: false, state: 'idle', route: 'unknown', hostKey: null });
  const [fileConfig, setFileConfig] = useState({ role: 'controller', coordinator: '', peerLocator: '', peerFingerprint: '', bindAddress: '0.0.0.0:0', iceMode: 'automatic', stunUrls: '' });
  const [files, setFiles] = useState({ active: false, state: 'idle', route: 'unknown', capabilities: null, local: [], remote: [], transfers: {} });
  const [filePaths, setFilePaths] = useState({ local: '0/.', remote: '0/.', source: '', destination: '', collision: 'fail' });
  const [deviceDraft, setDeviceDraft] = useState({ name: '', deviceId: '' });
  const imageRef = useRef(null);
  const terminalElementRef = useRef(null);
  const terminalRef = useRef(null);
  const fitRef = useRef(null);
  const sshControlRef = useRef(false);

  const canControl = desktop.active && config.role === 'controller' && config.controlRequested && desktop.control;
  const frameUrl = useMemo(() => desktop.frame ? `data:image/jpeg;base64,${desktop.frame.jpeg}` : '', [desktop.frame]);
  sshControlRef.current = ssh.active && sshConfig.role === 'controller';

  useEffect(() => {
    window.wiidesk.listBookmarks().then(setBookmarks).catch(() => setNotice('Could not read saved device bookmarks. Existing data was not changed.'));
    window.wiidesk.getAgentStatus().then(setAgent).catch(() => setNotice('Local agent status is unavailable.'));
    window.wiidesk.getDesktopStatus().then(status => setDesktop(previous => ({ ...previous, ...status }))).catch(() => {});
    window.wiidesk.getSshStatus().then(status => setSsh(previous => ({ ...previous, ...status }))).catch(() => {});
    window.wiidesk.getFileStatus().then(status => setFiles(previous => ({ ...previous, ...status }))).catch(() => {});
    return window.wiidesk.onDesktopEvent(event => {
      if (event.type === 'state') setDesktop(previous => ({ ...previous, active: true, state: event.state, route: event.route }));
      if (event.type === 'host_indicator') setDesktop(previous => ({ ...previous, hostActive: event.active }));
      if (event.type === 'monitor') setDesktop(previous => ({ ...previous, monitor: event.monitor, keyboardLayout: event.keyboard_layout }));
      if (event.type === 'frame') setDesktop(previous => ({ ...previous, active: true, frame: event }));
      if (event.type === 'stats') setDesktop(previous => ({ ...previous, stats: event }));
      if (event.type === 'control') setDesktop(previous => ({ ...previous, control: event.allowed }));
      if (event.type === 'failure') {
        setDesktop(previous => ({ ...previous, active: false, state: 'failed', control: false, hostActive: false }));
        setNotice(`Native desktop session failed safely: ${event.code.replaceAll('_', ' ')}.`);
      }
      if (event.type === 'closed') {
        setDesktop(previous => ({ ...previous, active: false, state: 'closed', route: event.route, control: false, hostActive: false }));
        setNotice('Desktop session closed. The host released any held remote input.');
      }
    });
  }, []);

  useEffect(() => {
    if (!terminalElementRef.current) return undefined;
    const terminal = new Terminal({ convertEol: true, cursorBlink: true, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 13, scrollback: 3_000, theme: { background: '#080d16', foreground: '#e9eef8', cursor: '#76e0c3' } });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(terminalElementRef.current);
    fit.fit();
    terminal.writeln('WII Ultra Desk SSH terminal — host-key verification and authentication are performed by OpenSSH.');
    const input = terminal.onData(data => {
      if (!sshControlRef.current) return;
      window.wiidesk.sendSshCommand({ type: 'input', data: textToBase64(data) }).catch(error => setNotice(error.message || 'SSH terminal input was not accepted.'));
    });
    const resize = terminal.onResize(({ cols, rows }) => {
      if (!sshControlRef.current) return;
      window.wiidesk.sendSshCommand({ type: 'resize', cols, rows }).catch(() => {});
    });
    const observer = new ResizeObserver(() => { try { fit.fit(); } catch {} });
    observer.observe(terminalElementRef.current);
    terminalRef.current = terminal;
    fitRef.current = fit;
    return () => { observer.disconnect(); input.dispose(); resize.dispose(); terminal.dispose(); terminalRef.current = null; fitRef.current = null; };
  }, []);

  useEffect(() => window.wiidesk.onSshEvent(event => {
    if (event.type === 'state') setSsh(previous => ({ ...previous, active: true, state: event.state, route: event.route }));
    if (event.type === 'terminal') terminalRef.current?.write(base64ToBytes(event.data));
    if (event.type === 'host_key') {
      setSsh(previous => ({ ...previous, hostKey: event.state }));
      setNotice(event.state === 'changed_key_rejected' ? 'SSH rejected a changed host key. Do not override this warning; investigate the endpoint identity.' : 'OpenSSH is waiting for first-use host-key approval in the terminal.');
    }
    if (event.type === 'failure') { setSsh(previous => ({ ...previous, active: false, state: 'failed' })); setNotice(`SSH session failed safely: ${event.code.replaceAll('_', ' ')}.`); }
    if (event.type === 'closed') { setSsh(previous => ({ ...previous, active: false, state: 'closed', route: event.route })); terminalRef.current?.writeln('\r\n[SSH session closed]'); }
  }), []);

  useEffect(() => window.wiidesk.onFileEvent(event => {
    if (event.type === 'state') setFiles(previous => ({ ...previous, active: true, state: event.state, route: event.route }));
    if (event.type === 'capabilities') setFiles(previous => ({ ...previous, capabilities: { read: event.read, write: event.write } }));
    if (event.type === 'entries') setFiles(previous => ({ ...previous, [event.pane]: event.entries }));
    if (event.type === 'transfer') setFiles(previous => ({ ...previous, transfers: { ...previous.transfers, [event.transfer_id]: event } }));
    if (event.type === 'failure') { setFiles(previous => ({ ...previous, active: false, state: 'failed' })); setNotice(`File session failed safely: ${event.code.replaceAll('_', ' ')}.`); }
    if (event.type === 'closed') setFiles(previous => ({ ...previous, active: false, state: 'closed', route: event.route }));
  }), []);

  useEffect(() => {
    const release = () => { if (canControl) window.wiidesk.sendDesktopInput({ type: 'release_all' }).catch(() => {}); };
    window.addEventListener('blur', release);
    return () => window.removeEventListener('blur', release);
  }, [canControl]);

  const updateConfig = event => {
    const { name, value, checked, type } = event.target;
    setConfig(previous => ({ ...previous, [name]: type === 'checkbox' ? checked : value }));
  };
  const updateSshConfig = event => {
    const { name, value } = event.target;
    setSshConfig(previous => ({ ...previous, [name]: value }));
  };
  const updateFileConfig = event => {
    const { name, value } = event.target;
    setFileConfig(previous => ({ ...previous, [name]: value }));
  };
  const updateFilePath = event => {
    const { name, value } = event.target;
    setFilePaths(previous => ({ ...previous, [name]: value }));
  };
  const sendInput = input => {
    if (!canControl) return;
    window.wiidesk.sendDesktopInput(input).catch(error => setNotice(error.message || 'Remote input was not accepted.'));
  };
  const pointerPosition = event => {
    const box = imageRef.current?.getBoundingClientRect();
    if (!box || box.width < 1 || box.height < 1) return null;
    return { x: Math.min(1, Math.max(0, (event.clientX - box.left) / box.width)), y: Math.min(1, Math.max(0, (event.clientY - box.top) / box.height)) };
  };
  const onViewportKey = event => {
    if (!canControl || event.repeat || !namedKeys[event.key]) return;
    event.preventDefault();
    sendInput({ type: 'key', key: namedKeys[event.key], pressed: event.type === 'keydown' });
  };
  const start = async event => {
    event.preventDefault();
    try {
      const status = await window.wiidesk.startDesktop({
        ...config, monitorId: config.monitorId === '' ? null : Number(config.monitorId),
        stunUrls: config.stunUrls.split(',').map(value => value.trim()).filter(Boolean)
      });
      setDesktop(previous => ({ ...previous, ...status, state: 'connecting', route: 'unknown', control: false, frame: null }));
      setNotice('Session requested. The native agent validates identity, a fresh authorization and TURN credentials before capture starts.');
    } catch (error) { setNotice(error.message || 'Desktop session could not start.'); }
  };
  const stop = async () => {
    try { await window.wiidesk.stopDesktop(); } catch (error) { setNotice(error.message || 'Could not disconnect the session.'); }
  };
  const startSsh = async event => {
    event.preventDefault();
    try {
      const status = await window.wiidesk.startSsh({ ...sshConfig, stunUrls: sshConfig.stunUrls.split(',').map(value => value.trim()).filter(Boolean) });
      setSsh(previous => ({ ...previous, ...status, state: 'connecting', route: 'unknown', hostKey: null }));
      terminalRef.current?.writeln('\r\n[Requesting authenticated SSH tunnel…]');
    } catch (error) { setNotice(error.message || 'SSH session could not start.'); }
  };
  const stopSsh = async () => {
    try { await window.wiidesk.stopSsh(); } catch (error) { setNotice(error.message || 'Could not disconnect SSH.'); }
  };
  const startFiles = async event => {
    event.preventDefault();
    try {
      const status = await window.wiidesk.startFile({ ...fileConfig, stunUrls: fileConfig.stunUrls.split(',').map(value => value.trim()).filter(Boolean) });
      setFiles(previous => ({ ...previous, ...status, state: 'connecting', route: 'unknown', capabilities: null }));
    } catch (error) { setNotice(error.message || 'File session could not start.'); }
  };
  const stopFiles = async () => {
    try { await window.wiidesk.stopFile(); } catch (error) { setNotice(error.message || 'Could not disconnect the file session.'); }
  };
  const disconnectUnattended = async () => {
    try {
      const status = await window.wiidesk.disconnectUnattended();
      setAgent(status);
      setNotice('Local Disconnect sent to the native service. Active unattended channels were terminated and resources released.');
    } catch (error) { setNotice(error.message || 'Could not disconnect unattended sessions.'); }
  };
  const disableUnattended = async () => {
    try {
      const status = await window.wiidesk.disableUnattended();
      setAgent(status);
      setNotice('Unattended access is now disabled locally. New background connections fail closed.');
    } catch (error) { setNotice(error.message || 'Could not disable unattended access.'); }
  };
  const fileCommand = async command => {
    try { await window.wiidesk.sendFileCommand(command); } catch (error) { setNotice(error.message || 'File operation was not accepted.'); }
  };
  const listLocal = () => fileCommand({ type: 'list_local', path: filePaths.local });
  const listRemote = () => fileCommand({ type: 'list_remote', path: filePaths.remote });
  const transfer = type => fileCommand({ type, transfer_id: transferId(), source: filePaths.source, destination: filePaths.destination, collision: filePaths.collision });
  const saveBookmark = async event => {
    event.preventDefault();
    try {
      setBookmarks(await window.wiidesk.saveBookmark(deviceDraft));
      setDeviceDraft({ name: '', deviceId: '' });
      setNotice('Bookmark saved. It does not grant access or establish trust.');
    } catch (error) { setNotice(error.message || 'Could not save bookmark.'); }
  };

  return <main>
    <header><div><div className="eyebrow">WII ULTRA DESK</div><h1>Authenticated remote desktop</h1></div><span className={`badge ${desktop.hostActive ? 'host-active' : ''}`}>{desktop.hostActive ? 'HOST: sharing active' : desktop.active ? 'Session active' : 'No session'}</span></header>
    <p className="intro">The native agent is the host boundary: it captures only after a current <code>desktop.view</code> grant and injects input only after a current <code>desktop.control</code> grant.</p>
    <section className="notice" role="status">{notice}</section>
    <div className="grid">
      <section><h2>Local trust and connectivity</h2><dl className="status-list">
        <Status label="Agent" value={agent?.agent === 'connected' ? 'Connected' : 'Native session agent required'} />
        <Status label="Identity" value={agent?.identity === 'available' ? 'Available' : 'Verified by native agent'} />
        <Status label="Unattended" value={agent?.unattendedEnabled ? `Enabled: ${agent.unattendedScopes.join(', ')}` : 'Off'} />
        <Status label="Background channels" value={String(agent?.activeUnattendedSessions ?? 0)} />
        <Status label="Transport" value={desktop.state ?? 'idle'} />
        <Status label="Route" value={routeLabel(desktop.route)} />
        <Status label="Control" value={desktop.control ? 'Host-authorized' : config.controlRequested ? 'Requested; awaiting host authorization' : 'View only'} />
        <Status label="Encoder" value={desktop.stats?.hardware_encoder_verified ? 'Hardware verified' : 'Bounded software JPEG'} />
      </dl><div className="actions"><button type="button" className="secondary" disabled={!agent?.unattendedEnabled} onClick={disconnectUnattended}>Disconnect unattended</button><button type="button" className="danger" disabled={!agent?.unattendedEnabled} onClick={disableUnattended}>Disable unattended access</button></div><p className="muted">These local actions require the authenticated native service. Bookmarks never grant access.</p></section>
      <section><h2>Saved devices</h2><form onSubmit={saveBookmark} className="bookmark-form"><label>Name<input required maxLength="80" value={deviceDraft.name} onChange={event => setDeviceDraft(previous => ({ ...previous, name: event.target.value }))} /></label><label>Locator label<input required pattern="[A-Za-z0-9_-]{6,80}" value={deviceDraft.deviceId} onChange={event => setDeviceDraft(previous => ({ ...previous, deviceId: event.target.value }))} /></label><button>Save bookmark</button></form><ul>{bookmarks.length ? bookmarks.map(device => <li key={device.deviceId}><strong>{device.name}</strong><span>{device.deviceId} · locator only</span></li>) : <li>No saved devices.</li>}</ul></section>
    </div>
    <section><h2>Desktop session</h2><form className="session-form" onSubmit={start}>
      <label>Role<select name="role" value={config.role} onChange={updateConfig}><option value="controller">Controller (view remote desktop)</option><option value="host">Host (share this desktop)</option></select></label>
      <label>Coordinator WSS URL<input name="coordinator" required placeholder="wss://coord.example/v1/connect" value={config.coordinator} onChange={updateConfig} /></label>
      <label>Verified peer locator<input name="peerLocator" required pattern="[A-Za-z0-9_-]{22}" value={config.peerLocator} onChange={updateConfig} /></label>
      <label>Verified peer fingerprint<input name="peerFingerprint" required pattern="[a-f0-9]{64}" value={config.peerFingerprint} onChange={updateConfig} /></label>
      <label>Bind address<input name="bindAddress" required value={config.bindAddress} onChange={updateConfig} /></label>
      <label>STUN URLs (comma separated)<input name="stunUrls" placeholder="stun:stun.example:3478" value={config.stunUrls} onChange={updateConfig} /></label>
      <label>ICE route<select name="iceMode" value={config.iceMode} onChange={updateConfig}><option value="automatic">Automatic</option><option value="relay-only">Relay only (diagnostic)</option></select></label>
      <label>Quality<select name="quality" value={config.quality} onChange={updateConfig}>{Object.entries(qualityLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>Host monitor ID (optional)<input name="monitorId" type="number" min="0" step="1" value={config.monitorId} onChange={updateConfig} /></label>
      <label className="check"><input name="controlRequested" type="checkbox" checked={config.controlRequested} onChange={updateConfig} /> Request remote control (the host must separately allow it)</label>
      <div className="actions"><button disabled={desktop.active}>Start authenticated session</button><button type="button" className="secondary" disabled={!desktop.active} onClick={stop}>Disconnect</button></div>
    </form></section>
    <section className="remote-session"><div className="remote-heading"><div><h2>Remote view</h2><p className="muted">{desktop.monitor ? `${desktop.monitor.name} · ${desktop.monitor.width}×${desktop.monitor.height} · scale ${desktop.monitor.scale_factor}` : 'No remote monitor announced.'}</p></div><div className="stats">{desktop.stats ? <>{desktop.stats.sent_frames}/{desktop.stats.captured_frames} frames · {desktop.stats.dropped_frames} dropped · {desktop.stats.encode_ms} ms encode</> : 'Waiting for native stream statistics'}</div></div>
      <div className={`viewport ${canControl ? 'interactive' : ''}`} tabIndex="0" role="application" aria-label="Remote desktop viewport" onKeyDown={onViewportKey} onKeyUp={onViewportKey} onMouseMove={event => { const position = pointerPosition(event); if (position) sendInput({ type: 'pointer', ...position }); }} onMouseDown={event => { const button = ['left', 'middle', 'right'][event.button]; if (button) { event.preventDefault(); sendInput({ type: 'button', button, pressed: true }); } }} onMouseUp={event => { const button = ['left', 'middle', 'right'][event.button]; if (button) sendInput({ type: 'button', button, pressed: false }); }} onMouseLeave={() => sendInput({ type: 'release_all' })} onWheel={event => { if (canControl) { event.preventDefault(); sendInput({ type: 'scroll', horizontal: Math.round(event.deltaX), vertical: Math.round(event.deltaY), smooth: config.quality === 'smooth-motion' }); } }}>
        {frameUrl ? <img ref={imageRef} src={frameUrl} alt="Live remote desktop" draggable="false" /> : <p>Frames appear here after an authenticated native session connects.</p>}
      </div>
      <div className="input-row"><input aria-label="Send Unicode text" disabled={!canControl} maxLength="256" placeholder={canControl ? 'Type text to send to the host' : 'Remote control is disabled'} onKeyDown={event => { if (event.key === 'Enter' && event.currentTarget.value) { sendInput({ type: 'text', text: event.currentTarget.value }); event.currentTarget.value = ''; } }} /><button type="button" className="secondary" disabled={!canControl} onClick={() => sendInput({ type: 'release_all' })}>Release held input</button></div>
    </section>
    <section><div className="remote-heading"><div><h2>SSH terminal</h2><p className="muted">The native host permits only its administrator-configured loopback SSH endpoint after a current <code>ssh</code> grant. OpenSSH, not an agent command shell, asks for host-key approval and authentication.</p></div><div className="stats">{ssh.active ? `${routeLabel(ssh.route)} · ${ssh.state}` : 'Disconnected'}</div></div>
      <form className="session-form compact-form" onSubmit={startSsh}>
        <label>Role<select name="role" value={sshConfig.role} onChange={updateSshConfig}><option value="controller">Controller (terminal)</option><option value="host">Host (approved local SSH only)</option></select></label>
        <label>SSH username<input name="username" required pattern="[A-Za-z0-9._-]{1,64}" autoComplete="username" value={sshConfig.username} onChange={updateSshConfig} /></label>
        <label>Coordinator WSS URL<input name="coordinator" required placeholder="wss://coord.example/v1/connect" value={sshConfig.coordinator} onChange={updateSshConfig} /></label>
        <label>Verified peer locator<input name="peerLocator" required pattern="[A-Za-z0-9_-]{22}" value={sshConfig.peerLocator} onChange={updateSshConfig} /></label>
        <label>Verified peer fingerprint<input name="peerFingerprint" required pattern="[a-f0-9]{64}" value={sshConfig.peerFingerprint} onChange={updateSshConfig} /></label>
        <label>Bind address<input name="bindAddress" required value={sshConfig.bindAddress} onChange={updateSshConfig} /></label>
        <label>STUN URLs (comma separated)<input name="stunUrls" placeholder="stun:stun.example:3478" value={sshConfig.stunUrls} onChange={updateSshConfig} /></label>
        <label>ICE route<select name="iceMode" value={sshConfig.iceMode} onChange={updateSshConfig}><option value="automatic">Automatic</option><option value="relay-only">Relay only (diagnostic)</option></select></label>
        <div className="actions"><button disabled={ssh.active}>Open authenticated SSH</button><button type="button" className="secondary" disabled={!ssh.active} onClick={stopSsh}>Disconnect SSH</button></div>
      </form>
      {ssh.hostKey === 'changed_key_rejected' && <p className="warning">Changed host key rejected. Do not bypass host-key checking.</p>}
      <div ref={terminalElementRef} className={`terminal-shell ${ssh.active && sshConfig.role === 'controller' ? 'terminal-active' : ''}`} aria-label="Integrated SSH terminal" />
    </section>
    <section><div className="remote-heading"><div><h2>Approved file transfer</h2><p className="muted">Paths are virtual (<code>0/…</code>) beneath roots configured by the native host. Read and write authorization are separate; rejected paths never leave the agent boundary.</p></div><div className="stats">{files.active ? `${routeLabel(files.route)} · ${files.state}` : 'Disconnected'}</div></div>
      <form className="session-form compact-form" onSubmit={startFiles}>
        <label>Role<select name="role" value={fileConfig.role} onChange={updateFileConfig}><option value="controller">Controller (browse and transfer)</option><option value="host">Host (approved roots)</option></select></label>
        <label>ICE route<select name="iceMode" value={fileConfig.iceMode} onChange={updateFileConfig}><option value="automatic">Automatic</option><option value="relay-only">Relay only (diagnostic)</option></select></label>
        <label>Coordinator WSS URL<input name="coordinator" required placeholder="wss://coord.example/v1/connect" value={fileConfig.coordinator} onChange={updateFileConfig} /></label>
        <label>Verified peer locator<input name="peerLocator" required pattern="[A-Za-z0-9_-]{22}" value={fileConfig.peerLocator} onChange={updateFileConfig} /></label>
        <label>Verified peer fingerprint<input name="peerFingerprint" required pattern="[a-f0-9]{64}" value={fileConfig.peerFingerprint} onChange={updateFileConfig} /></label>
        <label>Bind address<input name="bindAddress" required value={fileConfig.bindAddress} onChange={updateFileConfig} /></label>
        <label>STUN URLs (comma separated)<input name="stunUrls" placeholder="stun:stun.example:3478" value={fileConfig.stunUrls} onChange={updateFileConfig} /></label>
        <div className="actions"><button disabled={files.active}>Open authenticated files</button><button type="button" className="secondary" disabled={!files.active} onClick={stopFiles}>Disconnect files</button></div>
      </form>
      <div className="capability-line">Host files capability: {files.capabilities ? `${files.capabilities.read ? 'read' : 'no read'} / ${files.capabilities.write ? 'write' : 'no write'}` : 'waiting for host authorization'}</div>
      <div className="file-manager">
        <div className="file-pane"><div className="pane-heading"><h3>Local approved roots</h3><button type="button" className="secondary" disabled={!files.active || fileConfig.role !== 'controller'} onClick={listLocal}>List</button></div><label>Path<input name="local" value={filePaths.local} onChange={updateFilePath} placeholder="0/." /></label><ul className="file-list">{files.local.map(entry => <li key={entry.path}><button type="button" className="file-name" onClick={() => { setFilePaths(previous => ({ ...previous, source: entry.path, local: entry.kind === 'directory' ? entry.path : previous.local })); if (entry.kind === 'directory') fileCommand({ type: 'list_local', path: entry.path }); }}>{entry.kind === 'directory' ? '▸' : '•'} {entry.name}</button><span>{entry.kind === 'file' ? `${entry.size} B` : 'folder'}</span></li>)}</ul></div>
        <div className="file-pane"><div className="pane-heading"><h3>Remote approved roots</h3><button type="button" className="secondary" disabled={!files.active || fileConfig.role !== 'controller' || !files.capabilities?.read} onClick={listRemote}>List</button></div><label>Path<input name="remote" value={filePaths.remote} onChange={updateFilePath} placeholder="0/." /></label><ul className="file-list">{files.remote.map(entry => <li key={entry.path}><button type="button" className="file-name" onClick={() => { setFilePaths(previous => ({ ...previous, destination: entry.path, remote: entry.kind === 'directory' ? entry.path : previous.remote })); if (entry.kind === 'directory') fileCommand({ type: 'list_remote', path: entry.path }); }}>{entry.kind === 'directory' ? '▸' : '•'} {entry.name}</button><span>{entry.kind === 'file' ? `${entry.size} B` : 'folder'}</span></li>)}</ul></div>
      </div>
      <div className="transfer-controls"><label>Source virtual path<input name="source" value={filePaths.source} onChange={updateFilePath} placeholder="0/report.pdf" /></label><label>Destination virtual path<input name="destination" value={filePaths.destination} onChange={updateFilePath} placeholder="0/report.pdf" /></label><label>On collision<select name="collision" value={filePaths.collision} onChange={updateFilePath}><option value="fail">Fail safely</option><option value="replace">Atomically replace</option></select></label><div className="transfer-actions"><button type="button" disabled={!files.active || fileConfig.role !== 'controller' || !files.capabilities?.write} onClick={() => transfer('upload')}>Upload →</button><button type="button" className="secondary" disabled={!files.active || fileConfig.role !== 'controller' || !files.capabilities?.read} onClick={() => transfer('download')}>← Download</button></div></div>
      <ul className="transfer-list">{Object.values(files.transfers).map(item => <li key={item.transfer_id}><strong>{item.direction} · {item.status}</strong><span>{item.path} · {item.transferred}/{item.total} bytes</span>{item.status === 'running' && <button type="button" className="secondary" onClick={() => fileCommand({ type: 'cancel', transfer_id: item.transfer_id })}>Cancel</button>}</li>)}</ul>
    </section>
    <footer>Screen capture and input remain subject to operating-system permissions. SSH preserves OpenSSH host-key checks and user authentication; files remain inside approved roots and never create a general network proxy.</footer>
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
