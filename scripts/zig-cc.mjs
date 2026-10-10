#!/usr/bin/env node
import path from 'node:path';
import { spawn } from 'node:child_process';

const zigBinary = process.env.WII_ZIG_BINARY;
const zigTarget = process.env.WII_ZIG_TARGET;
if (!zigBinary || !path.isAbsolute(zigBinary) || !/^[a-z0-9_]+-(linux|windows)-gnu$/.test(zigTarget ?? '')) {
  throw new Error('zig-cc requires an absolute WII_ZIG_BINARY and a supported WII_ZIG_TARGET.');
}

const child = spawn(zigBinary, ['cc', '-target', zigTarget, ...process.argv.slice(2)], { stdio: 'inherit', windowsHide: true });
child.once('error', error => {
  process.stderr.write(`Could not start Zig: ${error.message}\n`);
  process.exitCode = 1;
});
child.once('exit', code => { process.exitCode = code ?? 1; });
