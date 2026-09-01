import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-field-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('Field declarations preserve Orb lineage and passive state evidence', () => {
  const result = spawnSync(executable, ['inspect', join(root, 'tests/fixtures/tranche-semantic/field.stellar'), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"kind":"field-layer"/);
  assert.match(result.stdout, /"field":"runtime"/);
  assert.match(result.stdout, /"orb":"signal-orb"/);
  assert.match(result.stdout, /"target":"workspace"/);
  assert.match(result.stdout, /"state":"active"/);
  assert.match(result.stdout, /"passive":true/);
  assert.match(result.stdout, /"executionEnabled":false/);
});

for (const [name, code] of [['field-unknown-orb.stellar', 'S2003'], ['field-invalid-state.stellar', 'S6201'], ['field-duplicate-field.stellar', 'S6201']] as const) {
  test(`${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
