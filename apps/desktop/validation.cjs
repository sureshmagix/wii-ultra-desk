function validateBookmark(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid bookmark');
  if (typeof value.name !== 'string' || !value.name.trim() || value.name.length > 80 ||
      /[\u0000-\u001f\u007f]/.test(value.name)) throw new Error('Invalid device name');
  if (typeof value.deviceId !== 'string' || !/^[A-Za-z0-9_-]{6,80}$/.test(value.deviceId)) {
    throw new Error('Device ID must contain 6–80 letters, numbers, underscores or hyphens');
  }
  // A bookmark never carries credentials, verified fingerprints or grants.
  return { name: value.name.trim(), deviceId: value.deviceId };
}
module.exports = { validateBookmark };
