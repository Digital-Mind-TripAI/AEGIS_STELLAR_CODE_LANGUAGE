import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-totem-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('Totem declarations preserve explicit parent/child lineage and Shortfall references without execution', () => {
  const result = spawnSync(executable, ['inspect', join(root, 'tests/fixtures/tranche-semantic/totem.stellar'), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"executionEnabled":false/);
  assert.match(result.stdout, /"kind":"totem-lineage"/);
  assert.match(result.stdout, /"totem":"mission"/);
  assert.match(result.stdout, /"children":\["scout"\]/);
  assert.match(result.stdout, /"shortfalls":\["missing-approval"\]/);
});

for (const [name, code] of [['totem-unknown-parent.stellar', 'S2003'], ['totem-bad-backlink.stellar', 'S2003'], ['totem-duplicate-child.stellar', 'S2002']] as const) {
  test(`Totem ${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
