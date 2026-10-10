import { build } from 'esbuild';
import path from 'node:path';
import { copyFile } from 'node:fs/promises';

await build({
  entryPoints: [path.join('apps', 'desktop', 'ui', 'renderer.jsx')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome142'],
  outfile: path.join('apps', 'desktop', 'ui', 'renderer.bundle.js'),
  sourcemap: false,
  legalComments: 'none',
  jsx: 'automatic'
});

await copyFile(
  path.join('node_modules', '@xterm', 'xterm', 'css', 'xterm.css'),
  path.join('apps', 'desktop', 'ui', 'xterm.css')
);
