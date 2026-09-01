import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-orb-'));
const executable = join(scratch, 'stellar.exe');
const fixture = join(root, 'tests/fixtures/tranche-semantic/orb.stellar');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('orb declarations bind a non-empty ordered set of declared elements without enabling execution', () => {
  const result = spawnSync(executable, ['inspect', fixture, '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"executionEnabled":false/);
  assert.match(result.stdout, /"kind":"orb-elements"/);
  assert.match(result.stdout, /"orb":"dispatcher"/);
  assert.match(result.stdout, /"elements":\["bridge","witness"\]/);
});

for (const [name, code] of [['orb-unknown-element.stellar', 'S2003'], ['orb-duplicate-element.stellar', 'S2002']] as const) {
  test(`orb ${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
