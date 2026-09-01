import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-actuator-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('Repair Actuator proposals link a Target, passive Totem, and linked Shortfall without execution', () => {
  const result = spawnSync(executable, ['inspect', join(root, 'tests/fixtures/tranche-semantic/actuator-proposal.stellar'), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"kind":"actuator-proposal"/);
  assert.match(result.stdout, /"authorizationRequired":true/);
  assert.match(result.stdout, /"executionEnabled":false/);
  assert.match(result.stdout, /"shortfall":"missing-approval"/);
});

for (const [name, code] of [['actuator-unknown-totem.stellar', 'S2003'], ['actuator-unlinked-shortfall.stellar', 'S2003'], ['actuator-missing-authorization.stellar', 'S3001']] as const) {
  test(`Actuator proposal ${name} is refused deterministically`, () => {
    const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(code));
  });
}
