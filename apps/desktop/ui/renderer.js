const list = document.querySelector('#devices');
const message = document.querySelector('#message');
function render(devices) {
  list.replaceChildren();
  if (devices.length === 0) {
    const item = document.createElement('li');
    item.textContent = 'No devices saved yet.';
    list.append(item);
  }
  for (const device of devices) {
    const item = document.createElement('li');
    const name = document.createElement('strong');
    name.textContent = device.name;
    const detail = document.createElement('span');
    detail.textContent = `${device.deviceId} · Not paired`;
    item.append(name, detail);
    list.append(item);
  }
}
document.querySelector('#bookmark-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    render(await window.wiidesk.saveBookmark({ name: document.querySelector('#device-name').value,
      deviceId: document.querySelector('#device-id').value }));
    message.textContent = 'Device bookmark saved. Access has not been granted.';
    event.target.reset();
  } catch { message.textContent = 'Could not save. Check the device details and local storage permissions.'; }
});
window.wiidesk.listBookmarks().then(render).catch(() => {
  message.textContent = 'Could not read saved devices. Existing data has not been overwritten.';
});
