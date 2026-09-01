import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-harmonic-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('harmonic signatures accept bounded metadata without opening execution or FFI', () => {
  const result = spawnSync(executable, ['inspect', join(root, 'tests/fixtures/tranche-semantic/harmonic.stellar'), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"executionEnabled":false/);
  assert.match(result.stdout, /"kind":"harmonic-signature"/);
  assert.match(result.stdout, /"parameters":\{"purity":0\.8,"drift":0\.1,"capture":0\.4,"witness":true,"eq":1\.0\}/);
});

for (const [name, code] of [
  ['harmonic-duplicate-parameter.stellar', 'S2002'],
  ['harmonic-out-of-range.stellar', 'S3001'],
  ['harmonic-unknown-parameter.stellar', 'S3001'],
  ['harmonic-witness-number.stellar', 'S3001'],
] as const) {
  test(`${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
