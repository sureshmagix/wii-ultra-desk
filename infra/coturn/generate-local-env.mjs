import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const destination = path.join(directory, '.env');
const secret = crypto.randomBytes(32).toString('base64url');
await fs.writeFile(destination, `WII_TURN_SHARED_SECRET=${secret}\nWII_TURN_REALM=wii-ultra-desk.local\n`, { mode: 0o600 });
console.log(`Generated ${destination}. It is ignored by Git and valid only for the local coturn fixture.`);
