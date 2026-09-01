import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-element-'));
const executable = join(scratch, 'stellar.exe');
const fixture = join(root, 'tests/fixtures/tranche-semantic/element.stellar');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));

test('element declarations type-check without enabling execution', () => {
  const result = spawnSync(executable, ['check', fixture, '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('duplicate element metadata is refused deterministically', () => {
  const source = 'element bridge / SignalBridge ( gain: 1, gain: 2 ) · function main ( ) / Result ( i32 ) ( return ok ( 0 ) · ) ·';
  const file = join(scratch, 'duplicate-element.stellar');
  writeFileSync(file, source, 'utf8');
  const result = spawnSync(executable, ['check', file, '--diagnostic-format', 'json'], { cwd: resolve('.'), encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /S2002/);
});
