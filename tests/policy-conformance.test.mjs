import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { authorizeUnattended } from '../packages/policy/unattended.mjs';

const vectors = JSON.parse(await readFile(new URL('../packages/policy/conformance-vectors.json', import.meta.url)));

for (const vector of vectors) {
  test(`policy conformance: ${vector.name}`, () => {
    assert.deepEqual(authorizeUnattended(vector.input), vector.expected);
  });
}
