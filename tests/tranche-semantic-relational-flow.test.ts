import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-flow-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('native relational-flow declarations emit deterministic passive evidence', () => {
  const fixture = join(root, 'tests/fixtures/tranche-semantic/relational-flow.stellar');
  const first = spawnSync(executable, ['inspect', fixture, '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  const second = spawnSync(executable, ['inspect', fixture, '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr); assert.equal(second.status, 0, second.stderr); assert.equal(first.stdout, second.stdout);
  assert.match(first.stdout, /"executionEnabled":false/); assert.match(first.stdout, /"kind":"relational-flow"/); assert.match(first.stdout, /"flow":"signal-path"/); assert.match(first.stdout, /"passive":true/); assert.match(first.stdout, /"effects":\[\]/); assert.match(first.stdout, /"capabilities":\[\]/);
});

for (const [name, code] of [['relational-flow-cycle.stellar', 'S6304'], ['relational-flow-duplicate-order.stellar', 'S6302'], ['relational-flow-unknown-endpoint.stellar', 'S6303']] as const) {
  test(`${name} is refused deterministically`, () => { const result = spawnSync(executable, ['check', join(root, 'tests/fixtures/tranche-semantic', name), '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' }); assert.equal(result.status, 1); assert.match(result.stderr, new RegExp(code)); });
}
