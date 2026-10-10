import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const sourceRoots = ['apps', 'services', 'packages', 'tests', 'scripts', 'infra'];
const extensions = new Set(['.js', '.cjs', '.mjs', '.jsx']);

async function collectJavaScript(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collectJavaScript(candidate));
    else if (entry.isFile() && extensions.has(path.extname(entry.name))) files.push(candidate);
  }
  return files;
}

const readme = await readFile(path.join(root, 'README.md'));
if (readme.includes(0)) {
  throw new Error('README.md contains a NUL byte; repair its encoding before committing.');
}

const files = (await Promise.all(sourceRoots.map(directory => collectJavaScript(path.join(root, directory)))))
  .flat()
  .sort();

for (const file of files) {
  if (path.extname(file) === '.jsx') {
    const source = await readFile(file, 'utf8');
    const { transform } = await import('esbuild');
    await transform(source, { loader: 'jsx', format: 'esm', target: 'es2022' });
    continue;
  }
  const result = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

console.log(`Syntax and repository-hygiene checks passed for ${files.length} JavaScript files.`);
