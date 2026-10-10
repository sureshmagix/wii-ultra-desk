#!/usr/bin/env node
// Generate the *server-local* coturn configuration. The input is intentionally
// outside the repository because it contains the TURN REST shared secret.
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

const REQUIRED = [
  'WII_TURN_SHARED_SECRET', 'WII_TURN_FQDN', 'WII_TURN_REALM',
  'WII_TURN_LISTEN_IP', 'WII_TURN_RELAY_IP', 'WII_TURN_PORT',
  'WII_TURN_TLS_PORT', 'WII_TURN_RELAY_MIN_PORT', 'WII_TURN_RELAY_MAX_PORT',
  'WII_TURN_USER_QUOTA', 'WII_TURN_TOTAL_QUOTA', 'WII_TURN_TLS_CERT',
  'WII_TURN_TLS_KEY', 'WII_TURN_URLS'
];

function fail(message) {
  throw new Error(`coturn staging configuration rejected: ${message}`);
}

function usage() {
  console.error('Usage: node scripts/utho/generate-coturn-config.mjs --env /protected/staging.env --out /etc/wii-ultra-desk/turnserver.conf');
  process.exitCode = 2;
}

function parseArguments(argumentsList) {
  if (argumentsList.length !== 4 || argumentsList[0] !== '--env' || argumentsList[2] !== '--out') return undefined;
  return { env: argumentsList[1], out: argumentsList[3] };
}

function parseEnvironment(source) {
  const values = Object.create(null);
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=([^\s#][^\r\n]*)$/.exec(trimmed);
    if (!match) fail(`line ${index + 1} must be an unquoted KEY=value assignment`);
    const [, key, value] = match;
    if (Object.hasOwn(values, key)) fail(`duplicate ${key}`);
    values[key] = value;
  }
  for (const [key, value] of Object.entries(values)) {
    if (/(change[-_ ]?me|replace[-_ ]?me|example|placeholder|todo|<|>)/i.test(value)) {
      fail(`${key} contains a placeholder`);
    }
  }
  for (const key of REQUIRED) {
    if (!values[key]) fail(`missing ${key}`);
  }
  return values;
}

function validDomain(value) {
  return value.length <= 253
    && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
}

function ipv4Number(value) {
  const pieces = value.split('.');
  if (pieces.length !== 4 || pieces.some(piece => !/^(0|[1-9][0-9]{0,2})$/.test(piece))) return undefined;
  const bytes = pieces.map(Number);
  if (bytes.some(byte => byte > 255)) return undefined;
  return (((bytes[0] << 24) >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]) >>> 0;
}

function inRange(value, first, last) {
  return value >= ipv4Number(first) && value <= ipv4Number(last);
}

function publicIpv4(value) {
  const number = ipv4Number(value);
  return number !== undefined
    && !inRange(number, '0.0.0.0', '0.255.255.255')
    && !inRange(number, '10.0.0.0', '10.255.255.255')
    && !inRange(number, '100.64.0.0', '100.127.255.255')
    && !inRange(number, '127.0.0.0', '127.255.255.255')
    && !inRange(number, '169.254.0.0', '169.254.255.255')
    && !inRange(number, '172.16.0.0', '172.31.255.255')
    && !inRange(number, '192.168.0.0', '192.168.255.255')
    && !inRange(number, '192.0.2.0', '192.0.2.255')
    && !inRange(number, '198.51.100.0', '198.51.100.255')
    && !inRange(number, '203.0.113.0', '203.0.113.255')
    && !inRange(number, '224.0.0.0', '255.255.255.255');
}

function relayIp(value) {
  if (net.isIP(value) !== 4 || value === '0.0.0.0') return false;
  const number = ipv4Number(value);
  return !inRange(number, '127.0.0.0', '127.255.255.255')
    && !inRange(number, '169.254.0.0', '169.254.255.255')
    && !inRange(number, '224.0.0.0', '255.255.255.255');
}

function integer(values, key, min, max) {
  const value = Number(values[key]);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${key} must be an integer from ${min} to ${max}`);
  return value;
}

function absolutePath(values, key) {
  if (!path.isAbsolute(values[key]) || values[key].includes('\0')) fail(`${key} must be an absolute path`);
  return values[key];
}

async function regularFile(value, key) {
  let stat;
  try {
    stat = await fs.stat(value);
  } catch {
    fail(`${key} does not exist or cannot be read by the generator`);
  }
  if (!stat.isFile()) fail(`${key} is not a regular file`);
}

function urls(values, port, tlsPort) {
  const entries = values.WII_TURN_URLS.split(',');
  if (entries.length !== 3 || new Set(entries).size !== 3 || entries.some(entry => entry.trim() !== entry)) {
    fail('WII_TURN_URLS must contain exactly three distinct, comma-separated URLs');
  }
  const expected = new Set([
    `turn:${values.WII_TURN_FQDN}:${port}?transport=udp`,
    `turn:${values.WII_TURN_FQDN}:${port}?transport=tcp`,
    `turns:${values.WII_TURN_FQDN}:${tlsPort}?transport=tcp`
  ]);
  if (entries.some(entry => !expected.has(entry))) {
    fail('WII_TURN_URLS must exactly describe UDP, TCP, and TLS listeners for WII_TURN_FQDN');
  }
}

function validate(values) {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(values.WII_TURN_SHARED_SECRET)) {
    fail('WII_TURN_SHARED_SECRET must be a non-default base64url secret of at least 256 bits');
  }
  if (new Set(values.WII_TURN_SHARED_SECRET).size < 16) {
    fail('WII_TURN_SHARED_SECRET has insufficient character diversity; generate it with a CSPRNG');
  }
  if (/(development|default|password|test[-_ ]?secret)/i.test(values.WII_TURN_SHARED_SECRET)) {
    fail('WII_TURN_SHARED_SECRET resembles a development/default secret');
  }
  if (!validDomain(values.WII_TURN_FQDN) || values.WII_TURN_REALM !== values.WII_TURN_FQDN) {
    fail('WII_TURN_FQDN must be a DNS name and WII_TURN_REALM must exactly match it');
  }
  if (values.WII_TURN_LISTEN_IP !== '0.0.0.0' && !relayIp(values.WII_TURN_LISTEN_IP)) {
    fail('WII_TURN_LISTEN_IP must be 0.0.0.0 or a routable IPv4 address');
  }
  if (!relayIp(values.WII_TURN_RELAY_IP)) fail('WII_TURN_RELAY_IP must be a routable local IPv4 address, not wildcard/loopback/link-local/multicast');
  if (values.WII_TURN_PUBLIC_IP) {
    if (!publicIpv4(values.WII_TURN_PUBLIC_IP) || values.WII_TURN_PUBLIC_IP === values.WII_TURN_RELAY_IP) {
      fail('WII_TURN_PUBLIC_IP must be a distinct public IPv4 address when NAT mapping is configured');
    }
  } else if (!publicIpv4(values.WII_TURN_RELAY_IP)) {
    fail('WII_TURN_RELAY_IP must be public when WII_TURN_PUBLIC_IP is omitted; configure explicit one-to-one NAT mapping otherwise');
  }
  const port = integer(values, 'WII_TURN_PORT', 1024, 65535);
  const tlsPort = integer(values, 'WII_TURN_TLS_PORT', 1024, 65535);
  if (port === tlsPort) fail('TURN UDP/TCP and TLS listener ports must differ');
  const relayMin = integer(values, 'WII_TURN_RELAY_MIN_PORT', 1024, 65535);
  const relayMax = integer(values, 'WII_TURN_RELAY_MAX_PORT', relayMin + 31, 65535);
  if (relayMax - relayMin + 1 > 20_000) fail('relay range exceeds the staging safety limit of 20,000 ports');
  if ([port, tlsPort].some(listener => listener >= relayMin && listener <= relayMax)) {
    fail('relay range must not include a TURN listener port');
  }
  const userQuota = integer(values, 'WII_TURN_USER_QUOTA', 1, 64);
  const totalQuota = integer(values, 'WII_TURN_TOTAL_QUOTA', userQuota, 4096);
  const cert = absolutePath(values, 'WII_TURN_TLS_CERT');
  const key = absolutePath(values, 'WII_TURN_TLS_KEY');
  urls(values, port, tlsPort);
  return { port, tlsPort, relayMin, relayMax, userQuota, totalQuota, cert, key };
}

function configuration(values, settings) {
  const externalMapping = values.WII_TURN_PUBLIC_IP
    ? `external-ip=${values.WII_TURN_PUBLIC_IP}/${values.WII_TURN_RELAY_IP}\n`
    : '';
  return `# Generated by scripts/utho/generate-coturn-config.mjs. Contains a secret: mode 0640.\n# Do not edit; change the protected staging.env then regenerate.\nlistening-port=${settings.port}\ntls-listening-port=${settings.tlsPort}\nlistening-ip=${values.WII_TURN_LISTEN_IP}\nrelay-ip=${values.WII_TURN_RELAY_IP}\n${externalMapping}fingerprint\nuse-auth-secret\nstatic-auth-secret=${values.WII_TURN_SHARED_SECRET}\nrealm=${values.WII_TURN_REALM}\nserver-name=${values.WII_TURN_FQDN}\ncert=${settings.cert}\npkey=${settings.key}\nmin-port=${settings.relayMin}\nmax-port=${settings.relayMax}\nuser-quota=${settings.userQuota}\ntotal-quota=${settings.totalQuota}\nstale-nonce=600\nmax-allocate-timeout=30\nno-cli\nno-loopback-peers\nno-multicast-peers\nno-software-attribute\nno-tlsv1\nno-tlsv1_1\nlog-file=stdout\npidfile=/run/wii-ultra-turn/turnserver.pid\n# Prevent TURN from becoming a path to VPS-local, CGNAT, or metadata networks.\ndenied-peer-ip=0.0.0.0-0.255.255.255\ndenied-peer-ip=10.0.0.0-10.255.255.255\ndenied-peer-ip=100.64.0.0-100.127.255.255\ndenied-peer-ip=127.0.0.0-127.255.255.255\ndenied-peer-ip=169.254.0.0-169.254.255.255\ndenied-peer-ip=172.16.0.0-172.31.255.255\ndenied-peer-ip=192.168.0.0-192.168.255.255\ndenied-peer-ip=224.0.0.0-255.255.255.255\ndenied-peer-ip=::1\ndenied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\ndenied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n`;
}

const args = parseArguments(process.argv.slice(2));
if (!args) {
  usage();
} else {
  try {
    const values = parseEnvironment(await fs.readFile(args.env, 'utf8'));
    const settings = validate(values);
    await regularFile(settings.cert, 'WII_TURN_TLS_CERT');
    await regularFile(settings.key, 'WII_TURN_TLS_KEY');
    await fs.mkdir(path.dirname(args.out), { recursive: true, mode: 0o750 });
    await fs.writeFile(args.out, configuration(values, settings), { mode: 0o640 });
    await fs.chmod(args.out, 0o640);
    console.log(`Generated protected coturn configuration at ${args.out}.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'coturn staging configuration rejected');
    process.exitCode = 1;
  }
}
