import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-gap-pause-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('Gap-Pause declarations emit passive orchestration evidence', () => {
  const result = spawnSync(executable, ['inspect', join(root, 'tests/fixtures/tranche-semantic/gap-pause.stellar'), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"kind":"gap-pause"/);
  assert.match(result.stdout, /"pauseId":"approval-gap"/);
  assert.match(result.stdout, /"legalContext":"orchestration-boundary"/);
  assert.match(result.stdout, /"effects":\["pause-control"\]/);
  assert.match(result.stdout, /"capabilities":\[\]/);
  assert.match(result.stdout, /"executionEnabled":false/);
});

for (const [name, code] of [['gap-pause-timeout.stellar', 'S6103'], ['gap-pause-unknown-field.stellar', 'S6101'], ['gap-pause-duplicate-field.stellar', 'S6101']] as const) {
  test(`${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
