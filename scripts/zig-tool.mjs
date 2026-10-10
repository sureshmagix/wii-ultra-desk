#!/usr/bin/env node
import path from 'node:path';
import { spawn } from 'node:child_process';

const zigBinary = process.env.WII_ZIG_BINARY;
const zigTarget = process.env.WII_ZIG_TARGET;
if (!zigBinary || !path.isAbsolute(zigBinary) || !/^[a-z0-9_]+-(linux|windows)-gnu$/.test(zigTarget ?? '')) {
  throw new Error('Zig target tools require an absolute WII_ZIG_BINARY and a supported WII_ZIG_TARGET.');
}

const executable = path.basename(process.argv[1]);
const command = executable.endsWith('-dlltool') ? 'dlltool'
  : executable.endsWith('-ranlib') ? 'ranlib'
    : executable.endsWith('-ar') ? 'ar'
      : 'cc';
const forwardedArguments = command === 'cc'
  ? process.argv.slice(2).filter(argument => !argument.startsWith('--target='))
  : process.argv.slice(2);
const argumentsList = command === 'cc'
  ? ['cc', '-target', zigTarget, ...forwardedArguments]
  : [command, ...forwardedArguments];
const child = spawn(zigBinary, argumentsList, { stdio: 'inherit', windowsHide: true });
child.once('error', error => {
  process.stderr.write(`Could not start Zig: ${error.message}\n`);
  process.exitCode = 1;
});
child.once('exit', code => { process.exitCode = code ?? 1; });
