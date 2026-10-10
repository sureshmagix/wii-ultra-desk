const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('wiidesk', Object.freeze({
  listBookmarks: () => ipcRenderer.invoke('bookmarks:list'),
  saveBookmark: value => ipcRenderer.invoke('bookmarks:save', value),
  getAgentStatus: () => ipcRenderer.invoke('agent:status'),
  disconnectUnattended: () => ipcRenderer.invoke('unattended:disconnect'),
  disableUnattended: () => ipcRenderer.invoke('unattended:disable'),
  getDesktopStatus: () => ipcRenderer.invoke('desktop:status'),
  startDesktop: value => ipcRenderer.invoke('desktop:start', value),
  stopDesktop: () => ipcRenderer.invoke('desktop:stop'),
  sendDesktopInput: value => ipcRenderer.invoke('desktop:input', value),
  onDesktopEvent: callback => {
    if (typeof callback !== 'function') throw new TypeError('desktop event callback required');
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('desktop:event', listener);
    return () => ipcRenderer.removeListener('desktop:event', listener);
  },
  getSshStatus: () => ipcRenderer.invoke('ssh:status'),
  startSsh: value => ipcRenderer.invoke('ssh:start', value),
  stopSsh: () => ipcRenderer.invoke('ssh:stop'),
  sendSshCommand: value => ipcRenderer.invoke('ssh:command', value),
  onSshEvent: callback => {
    if (typeof callback !== 'function') throw new TypeError('SSH event callback required');
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('ssh:event', listener);
    return () => ipcRenderer.removeListener('ssh:event', listener);
  },
  getFileStatus: () => ipcRenderer.invoke('file:status'),
  startFile: value => ipcRenderer.invoke('file:start', value),
  stopFile: () => ipcRenderer.invoke('file:stop'),
  sendFileCommand: value => ipcRenderer.invoke('file:command', value),
  onFileEvent: callback => {
    if (typeof callback !== 'function') throw new TypeError('file event callback required');
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('file:event', listener);
    return () => ipcRenderer.removeListener('file:event', listener);
  }
}));
