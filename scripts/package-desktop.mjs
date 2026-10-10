import { chmod, copyFile, mkdir, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';

const root = process.cwd();
const targets = Object.freeze({
  'mac-intel': Object.freeze({ platform: 'mac', arch: 'x64', cargoTarget: 'x86_64-apple-darwin', electronFlag: '--mac', electronTarget: 'dmg' }),
  'mac-silicon': Object.freeze({ platform: 'mac', arch: 'arm64', cargoTarget: 'aarch64-apple-darwin', electronFlag: '--mac', electronTarget: 'dmg' }),
  windows: Object.freeze({ platform: 'win', arch: 'x64', cargoTarget: 'x86_64-pc-windows-gnu', electronFlag: '--win', electronTarget: 'nsis', toolPrefix: 'x86_64-w64-mingw32' }),
  ubuntu: Object.freeze({ platform: 'linux', arch: 'x64', cargoTarget: 'x86_64-unknown-linux-gnu', electronFlag: '--linux', electronTarget: 'deb', zigTarget: 'x86_64-linux-gnu', toolPrefix: 'x86_64-linux-gnu' })
});

function selectedTarget(argumentsList) {
  if (argumentsList.length !== 2 || argumentsList[0] !== '--target' || !targets[argumentsList[1]]) {
    throw new Error(`Usage: node scripts/package-desktop.mjs --target <${Object.keys(targets).join('|')}>`);
  }
  return Object.freeze({ name: argumentsList[1], ...targets[argumentsList[1]] });
}

function run(command, argumentsList, environment = process.env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, argumentsList, { cwd: root, env: environment, stdio: 'inherit', windowsHide: true });
    child.once('error', error => reject(new Error(`Could not start ${command}: ${error.message}`)));
    child.once('exit', code => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${argumentsList.join(' ')} exited with code ${code ?? 'unknown'}`));
    });
  });
}

function capture(command, argumentsList) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, argumentsList, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', value => { stdout += value; });
    child.stderr.on('data', value => { stderr += value; });
    child.once('error', error => reject(new Error(`Could not start ${command}: ${error.message}`)));
    child.once('exit', code => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`${command} ${argumentsList.join(' ')} exited with code ${code ?? 'unknown'}: ${stderr.trim()}`));
    });
  });
}

const target = selectedTarget(process.argv.slice(2));
const binaryName = target.platform === 'win' ? 'wii-ultra-desk-agent.exe' : 'wii-ultra-desk-agent';
const agentOutput = path.join(root, 'agent', 'target', target.cargoTarget, 'release', binaryName);
const stagedDirectory = path.join(root, '.release-resources', 'agent', `${target.platform}-${target.arch}`);
const stagedBinary = path.join(stagedDirectory, binaryName);
const builder = path.join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'electron-builder.cmd' : 'electron-builder');
const cargoEnvironment = { ...process.env };

if (target.platform === 'win' && process.platform !== 'win32') {
  const toolchainDirectory = process.env.WII_WINDOWS_GNU_TOOLCHAIN_BIN;
  if (!toolchainDirectory || !path.isAbsolute(toolchainDirectory)) {
    throw new Error('WII_WINDOWS_GNU_TOOLCHAIN_BIN must be an absolute MinGW bin directory when building the Windows package off Windows.');
  }
  const compiler = path.join(toolchainDirectory, `${target.toolPrefix}-gcc`);
  if (!(await stat(compiler)).isFile()) throw new Error(`Windows cross-compiler not found: ${compiler}`);
  cargoEnvironment.PATH = `${toolchainDirectory}${path.delimiter}${cargoEnvironment.PATH ?? ''}`;
}

if (target.zigTarget) {
  const zigBinary = process.env.WII_ZIG_BINARY;
  if (!zigBinary || !path.isAbsolute(zigBinary)) throw new Error('WII_ZIG_BINARY must be an absolute path to Zig 0.17.0 for the Ubuntu package.');
  if (await capture(zigBinary, ['version']) !== '0.17.0') throw new Error('The Ubuntu package requires Zig 0.17.0.');
  cargoEnvironment.WII_ZIG_BINARY = zigBinary;
  cargoEnvironment.WII_ZIG_TARGET = target.zigTarget;
  const toolDirectory = path.join(root, '.release-resources', 'toolchain', target.cargoTarget);
  const toolNames = [`${target.toolPrefix}-gcc`, `${target.toolPrefix}-ar`, `${target.toolPrefix}-ranlib`];
  if (target.platform === 'win') toolNames.push(`${target.toolPrefix}-dlltool`);
  await rm(toolDirectory, { recursive: true, force: true });
  await mkdir(toolDirectory, { recursive: true });
  await Promise.all(toolNames.map(async toolName => {
    const toolPath = path.join(toolDirectory, toolName);
    await copyFile(path.join(root, 'scripts', 'zig-tool.mjs'), toolPath);
    await chmod(toolPath, 0o755);
  }));
  const cargoVariableName = target.cargoTarget.replaceAll('-', '_').toUpperCase();
  cargoEnvironment[`CARGO_TARGET_${cargoVariableName}_LINKER`] = path.join(root, 'scripts', 'zig-cc.mjs');
  cargoEnvironment[`CC_${cargoVariableName}`] = path.join(toolDirectory, `${target.toolPrefix}-gcc`);
  cargoEnvironment[`AR_${cargoVariableName}`] = path.join(toolDirectory, `${target.toolPrefix}-ar`);
  cargoEnvironment.PATH = `${toolDirectory}${path.delimiter}${cargoEnvironment.PATH ?? ''}`;
}

await run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build:desktop-ui']);
await run('cargo', ['build', '--manifest-path', 'agent/Cargo.toml', '--locked', '--release', '--target', target.cargoTarget], cargoEnvironment);

const sourceMetadata = await stat(agentOutput);
if (!sourceMetadata.isFile()) throw new Error(`Native agent build did not produce ${agentOutput}`);
await rm(stagedDirectory, { recursive: true, force: true });
await mkdir(stagedDirectory, { recursive: true });
await copyFile(agentOutput, stagedBinary);
if (target.platform !== 'win') await chmod(stagedBinary, sourceMetadata.mode & 0o777);

await run(builder, [target.electronFlag, target.electronTarget, `--${target.arch}`, '--publish', 'never']);
