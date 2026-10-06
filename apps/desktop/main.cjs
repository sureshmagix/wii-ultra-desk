const { app, BrowserWindow, ipcMain, session, protocol, net } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs/promises');
const { validateBookmark } = require('./validation.cjs');

protocol.registerSchemesAsPrivileged([{ scheme: 'wiidesk', privileges: {
  standard: true, secure: true, supportFetchAPI: true
} }]);
let mainWindow;
let writeQueue = Promise.resolve();
const allowedFiles = new Map([
  ['/index.html', 'index.html'], ['/renderer.js', 'renderer.js'], ['/styles.css', 'styles.css']
]);
const pageUrl = 'wiidesk://app/index.html';
const bookmarkFile = () => path.join(app.getPath('userData'), 'bookmarks.json');
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
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
