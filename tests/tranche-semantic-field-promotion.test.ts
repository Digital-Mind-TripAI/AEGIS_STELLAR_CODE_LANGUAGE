import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const contract = fs.readFileSync(path.join(root, 'evidence', 'stellar-field-layer-ratified-contract-v0.1.md'), 'utf8');
const closure = fs.readFileSync(path.join(root, 'evidence', 'stellar-field-native-promotion-closure-v0.1.md'), 'utf8');

test('Field Layer native promotion remains closed until source grammar is ratified', () => {
  assert.match(contract, /no native syntax promoted/);
  assert.match(contract, /explicit source spelling/);
  assert.match(closure, /shortfall retained/);
  assert.match(closure, /canonical declaration spelling/);
  assert.match(closure, /executionEnabled:false/);
});
