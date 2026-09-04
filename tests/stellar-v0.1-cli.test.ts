import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-test-'));
const executable = join(scratch, 'stellar.exe');

before(() => {
  execFileSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    join(root, 'tools/build-cli.ps1'), '-Output', executable,
  ], { cwd: resolve('.'), encoding: 'utf8', stdio: 'pipe' });
});

after(() => rmSync(scratch, { recursive: true, force: true }));

function run(args: string[]) {
  return spawnSync(executable, args, { cwd: resolve('.'), encoding: 'utf8' });
}

test('standalone CLI reports the bounded Windows x64 v0.1 identity', () => {
  const result = run(['version']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'Stellar 0.1.0 (windows-x86_64-msvc; stellar-lab-v0)');
});

test('check emits stable human and JSON diagnostics with spans and help', () => {
  const invalid = join(scratch, 'invalid.stellar');
  writeFileSync(invalid, 'element bridge / SignalBridge ( gain: 1 )', 'utf8');
  const human = run(['check', invalid]);
  assert.equal(human.status, 1);
  assert.match(human.stderr, /S1009/);
  assert.match(human.stderr, /1:42/);
  assert.match(human.stderr, /help: follow the v0.1 typed grammar/);
  const json = run(['check', invalid, '--diagnostic-format', 'json']);
  assert.equal(json.status, 1);
  const diagnostic = JSON.parse(json.stderr.trim());
  assert.deepEqual(diagnostic, {
    code: 'S1009', severity: 'error', message: "expected '·' after element",
    file: invalid.replaceAll('\\', '/'),
    span: { start: { offset: 41, line: 1, column: 42 }, end: { offset: 41, line: 1, column: 42 } },
    primarySpan: { start: { offset: 41, line: 1, column: 42 }, end: { offset: 41, line: 1, column: 42 } },
    secondarySpans: [],
    stage: 'lex-parse',
    help: 'follow the v0.1 typed grammar',
  });
});

test('formatter is canonical, ASCII-normalizing, and idempotent', () => {
  const source = join(scratch, 'format.stellar');
  writeFileSync(source, [
    'element   source / Signal();',
    'element target/Signal();',
    'flow signal-path/Relational(node:source/element,node:target/element,edge:supports-edge/supports(from:source,to:target,order:1,condition:eq>=0.8,condition:witness==true),state:declared,shortfall:pending-witness,gap_pause:awaiting-witness);',
    'function main()/Result(i32)(return ok(0););',
    '',
  ].join('\n'), 'utf8');
  const first = run(['fmt', source]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stdout, [
    'element source / Signal ( ) ·',
    'element target / Signal ( ) ·',
    'flow signal-path / Relational ( node: source / element, node: target / element, edge: supports-edge / supports ( from: source, to: target, order: 1, condition: eq >= 0.8, condition: witness == true ), state: declared, shortfall: pending-witness, gap_pause: awaiting-witness ) ·',
    'function main ( ) / Result ( i32 ) ( return ok ( 0 ) · ) ·',
    '',
  ].join('\n'));
  const canonical = join(scratch, 'canonical.stellar');
  writeFileSync(canonical, first.stdout, 'utf8');
  const second = run(['fmt', canonical]);
  assert.equal(second.stdout, first.stdout);
  assert.equal(run(['fmt', canonical, '--check']).status, 0);
  assert.equal(run(['fmt', source, '--check']).status, 1);
});

test('source manager rejects invalid UTF-8, NUL, and oversized input deterministically', () => {
  const nul = join(scratch, 'nul.stellar');
  writeFileSync(nul, Buffer.from('element x / T ( ) ·\0'));
  assert.match(run(['check', nul]).stderr, /S0002/);
  const huge = join(scratch, 'huge.stellar');
  writeFileSync(huge, 'x'.repeat(262_145), 'utf8');
  assert.match(run(['check', huge]).stderr, /S0001/);
  const badUtf8 = join(scratch, 'bad-utf8.stellar');
  writeFileSync(badUtf8, Buffer.from([0xc3, 0x28]));
  assert.match(run(['check', badUtf8]).stderr, /S0003/);
});

test('bounded parser skeleton accepts the reviewed Phase C source fixture', () => {
  const result = run(['check', resolve('native/stellar/tests/fixtures/phase-c-core.stellar')]);
  assert.equal(result.status, 0, result.stderr);
});

test('native CLI keeps the legacy Preview WAVE fixture outside the typed v0.1 boundary', () => {
  const result = run(['check', resolve('native/stellar/tests/fixtures/signal-bridge.stellar')]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /S1009/);
  assert.match(result.stderr, /expected '\/' before relational-flow kind/);
});

test('manifest and lock inspection canonicalize, hash, and reject tamper or path escape', () => {
  const packageRoot = join(scratch, 'package');
  mkdirSync(packageRoot, { recursive: true });
  writeFileSync(join(packageRoot, 'main.stellar'), 'element bridge / SignalBridge ( gain: 1 ) ·\n', 'utf8');
  const manifest = join(packageRoot, 'stellar.package.json');
  writeFileSync(manifest, JSON.stringify({
    schema: 'stellar.package/v0.1', name: 'sample', version: '0.1.0', target: 'windows-x86_64-msvc',
    profile: 'stellar-lab-v0', entry: 'main.stellar', modules: ['main.stellar'], relics: [], capabilities: [],
  }, null, 2), 'utf8');
  const first = run(['inspect-manifest', manifest, '--write-lock']);
  assert.equal(first.status, 0, first.stderr);
  const inspected = JSON.parse(first.stdout);
  assert.match(inspected.integrity, /^sha256:[a-f0-9]{64}$/);
  assert.match(inspected.moduleHashes['main.stellar'], /^sha256:[a-f0-9]{64}$/);
  assert.equal(inspected.integrity, `sha256:${createHash('sha256').update(JSON.stringify(inspected.canonicalManifest)).digest('hex')}`);
  assert.equal(inspected.moduleHashes['main.stellar'], `sha256:${createHash('sha256').update(readFileSync(join(packageRoot, 'main.stellar'))).digest('hex')}`);
  const lock = JSON.parse(readFileSync(join(packageRoot, 'stellar.lock.json'), 'utf8'));
  assert.equal(lock.packageIntegrity, inspected.integrity);
  assert.equal(run(['inspect-manifest', manifest, '--verify-lock']).status, 0);
  writeFileSync(join(packageRoot, 'main.stellar'), 'element changed / SignalBridge ( gain: 1 ) ·\n', 'utf8');
  const tampered = run(['inspect-manifest', manifest, '--verify-lock']);
  assert.equal(tampered.status, 1);
  assert.match(tampered.stderr, /S5003/);
  writeFileSync(manifest, readFileSync(manifest, 'utf8').replace('main.stellar', '../escape.stellar'), 'utf8');
  const escaped = run(['inspect-manifest', manifest]);
  assert.equal(escaped.status, 1);
  assert.match(escaped.stderr, /S5002/);
});

test('repeated manifest inspection is byte-deterministic', () => {
  const manifest = resolve('native/stellar/v0_1/tests/fixtures/minimal/stellar.package.json');
  const first = run(['inspect-manifest', manifest]);
  const second = run(['inspect-manifest', manifest]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.stdout, first.stdout);
});
