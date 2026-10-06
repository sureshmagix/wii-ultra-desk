const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('wiidesk', Object.freeze({
  listBookmarks: () => ipcRenderer.invoke('bookmarks:list'),
  saveBookmark: value => ipcRenderer.invoke('bookmarks:save', value)
}));
