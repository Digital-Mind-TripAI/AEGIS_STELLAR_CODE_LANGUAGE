import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const fixtureRoot = join(root, 'tests/fixtures/tranche2');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-tranche2-'));
const executable = join(scratch, 'stellar.exe');
before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));
const run = (args: string[]) => spawnSync(executable, args, { cwd: resolve('.'), encoding: 'utf8' });
const inspect = (name: string) => {
  const result = run(['inspect-package', join(fixtureRoot, name, 'stellar.package.json')]);
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  return JSON.parse(result.stdout);
};

test('three structurally distinct multi-module/RELIC packages resolve deterministically', () => {
  for (const name of ['chain', 'diamond', 'relic']) {
    const first = run(['inspect-package', join(fixtureRoot, name, 'stellar.package.json')]);
    const second = run(['inspect-package', join(fixtureRoot, name, 'stellar.package.json')]);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(second.stdout, first.stdout);
    const result = JSON.parse(first.stdout);
    assert.equal(result.profile, 'stellar-package-v0.1');
    assert.equal(result.executionEnabled, false);
    assert.deepEqual({ required: result.effects.required, imports: result.effects.imports }, { required: [], imports: [] });
    assert.match(result.effects.hash, /^sha256:[a-f0-9]{64}$/);
    assert.match(result.dependencyGraphHash, /^sha256:[a-f0-9]{64}$/);
    assert.match(result.symbolTableHash, /^sha256:[a-f0-9]{64}$/);
  }
});

test('diamond package has deterministic DAG order, imports, exports and unique mangled symbols', () => {
  const result = inspect('diamond');
  assert.deepEqual(result.topologicalOrder, ['base', 'left', 'right', 'app']);
  assert.deepEqual(result.modules.app.dependencies, ['left', 'right']);
  const symbols = Object.values(result.symbols).map((item: any) => item.mangled);
  assert.equal(new Set(symbols).size, symbols.length);
  assert.ok(symbols.every((symbol: any) => /^stellar_v01_m[0-9a-f]+_s[0-9a-f]+_h[0-9a-f]{16}$/.test(symbol)));
});

test('RELIC interface is target/profile/ABI compatible, content-addressed and capability-free', () => {
  const result = inspect('relic');
  assert.equal(result.relics['core.checked'].abi, 'stellar-win64-v0.1');
  assert.equal(result.relics['core.checked'].version, '0.1.0');
  assert.match(result.relics['core.checked'].contentHash, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(result.relics['core.checked'].effects, []);
});

test('per-module COFF plan is inspect-only and records typed/source/interface evidence', () => {
  const result = inspect('chain');
  for (const plan of result.coffPlan) {
    assert.equal(plan.target, 'windows-x86_64-msvc');
    assert.equal(plan.format, 'COFF-x64');
    assert.equal(plan.objectEmitted, false);
    assert.equal(plan.executableLinked, false);
    assert.match(plan.sourceHash, /^sha256:[a-f0-9]{64}$/);
    assert.match(plan.typedEvidenceHash, /^sha256:[a-f0-9]{64}$/);
    for (const field of ['interfaceHash', 'dependencyGraphHash', 'symbolTableHash', 'effectsHash', 'planHash']) assert.match(plan[field], /^sha256:[a-f0-9]{64}$/, field);
    assert.equal(plan.abi, 'stellar-win64-v0.1');
    assert.equal(plan.objectHash, null);
    assert.ok(plan.objectName.endsWith('.obj'));
  }
});

test('canonical dependency lock binds graph, symbols, sources and RELICs and refuses tamper', () => {
  const target = join(scratch, 'lock-package');
  cpSync(join(fixtureRoot, 'chain'), target, { recursive: true });
  const manifest = join(target, 'stellar.package.json');
  const written = run(['inspect-package', manifest, '--write-dependency-lock']);
  assert.equal(written.status, 0, written.stderr);
  const lockPath = join(target, 'stellar.dependency.lock.json');
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  assert.equal(lock.schema, 'stellar.dependency-lock/v0.1');
  assert.match(lock.integrity, /^sha256:[a-f0-9]{64}$/);
  assert.equal(run(['check-package', manifest, '--verify-dependency-lock']).status, 0);
  writeFileSync(join(target, 'math.stellar'), readFileSync(join(target, 'math.stellar'), 'utf8').replace('add ( value, 1 )', 'add ( value, 2 )'), 'utf8');
  const tampered = run(['check-package', manifest, '--verify-dependency-lock', '--diagnostic-format', 'json']);
  assert.equal(tampered.status, 1);
  assert.match(tampered.stderr, /S5003/);

  const relicTarget = join(scratch, 'lock-relic-package');
  cpSync(join(fixtureRoot, 'relic'), relicTarget, { recursive: true });
  const relicManifest = join(relicTarget, 'stellar.package.json');
  assert.equal(run(['inspect-package', relicManifest, '--write-dependency-lock']).status, 0);
  const relicPath = join(relicTarget, 'relics/core.checked.relic.json');
  writeFileSync(relicPath, `${readFileSync(relicPath, 'utf8')}\n`, 'utf8');
  const relicTamper = run(['check-package', relicManifest, '--verify-dependency-lock', '--diagnostic-format', 'json']);
  assert.equal(relicTamper.status, 1);
  assert.match(relicTamper.stderr, /S5003/);
});

test('published package contract fixes mangling, ABI, dependency lock and non-execution boundary', () => {
  const contract = readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_PACKAGE_FORMAT.md'), 'utf8');
  assert.match(contract, /stellar_v01_m<module-utf8-hex>_s<symbol-utf8-hex>_h<signature-sha256-16>/);
  assert.match(contract, /stellar-win64-v0\.1/);
  assert.match(contract, /objectEmitted.*false/is);
  assert.match(contract, /checksum integrity is not authorization/i);
  assert.match(contract, /Custodian\/Steward-issued capability contract/i);
  assert.match(contract, /OS-enforced native process isolation/i);
});

function makePackage(name: string, modules: Record<string, string>, relic?: string) {
  const packageRoot = join(scratch, name);
  mkdirSync(packageRoot, { recursive: true });
  for (const [path, source] of Object.entries(modules)) {
    mkdirSync(dirname(join(packageRoot, path)), { recursive: true });
    writeFileSync(join(packageRoot, path), source, 'utf8');
  }
  if (relic) { mkdirSync(join(packageRoot, 'relics'), { recursive: true }); writeFileSync(join(packageRoot, 'relics/test.json'), relic, 'utf8'); }
  const manifest = { schema:'stellar.package/v0.1', name, version:'0.1.0', target:'windows-x86_64-msvc', profile:'stellar-lab-v0', entry:Object.keys(modules)[0], modules:Object.keys(modules), relics:relic?['relics/test.json']:[], capabilities:[] };
  writeFileSync(join(packageRoot, 'stellar.package.json'), JSON.stringify(manifest), 'utf8');
  return join(packageRoot, 'stellar.package.json');
}

const fn = (module: string, directives = '', body = 'return ok ( value ) ·') => `module ${module} ·\n${directives}export value_of ·\nfunction value_of ( value / i32 ) / Result ( i32 ) ( ${body} ) ·\n`;

const negativePackages: Array<[string, () => string, RegExp]> = [
  ['cycle', () => makePackage('cycle', {
    'a.stellar':'module a ·\nimport b / from_b ·\nexport from_a ·\nfunction from_a ( value / i32 ) / Result ( i32 ) ( return ok ( value ) · ) ·\n',
    'b.stellar':'module b ·\nimport a / from_a ·\nexport from_b ·\nfunction from_b ( value / i32 ) / Result ( i32 ) ( return ok ( value ) · ) ·\n',
  }), /S4004/],
  ['duplicate-module-id', () => makePackage('duplicate-module-id', { 'a.stellar':fn('same'), 'b.stellar':fn('same') }), /S4001/],
  ['missing-symbol', () => makePackage('missing-symbol', { 'a.stellar':fn('a','import b / absent ·\n'), 'b.stellar':fn('b') }), /S4002/],
  ['import-name-conflict', () => makePackage('import-name-conflict', { 'app.stellar':fn('app','import left / value_of ·\nimport right / value_of ·\n'), 'left.stellar':fn('left'), 'right.stellar':fn('right') }), /S4002/],
  ['duplicate-export', () => makePackage('duplicate-export', { 'main.stellar':fn('main','export value_of ·\n') }), /S4002/],
  ['symbol-type-mismatch', () => makePackage('symbol-type-mismatch', {
    'app.stellar':'module app ·\nimport lib / value_of ·\nexport main ·\nfunction main ( flag / bool ) / Result ( i32 ) ( return ok ( try_value ( value_of ( flag ) ) ) · ) ·\n',
    'lib.stellar':fn('lib'),
  }), /S2004/],
];
for (const [name, create, expected] of negativePackages) test(`refuses ${name}`, () => { const result=run(['check-package', create(), '--diagnostic-format', 'json']); assert.equal(result.status,1); assert.match(result.stderr,expected); });

test('refuses RELIC target, ABI, hash/interface tamper and effects', () => {
  const base = { schema:'stellar.relic-interface/v0.1', name:'bad.relic', version:'0.1.0', target:'linux-x86_64', profile:'stellar-lab-v0', abi:'c', exports:[{name:'value_of',parameters:['i32'],result:'i32'}], effects:[], imports:[] };
  for (const [field, value] of [['target','linux-x86_64'], ['abi','c'], ['profile','wrong'], ['effects',['windows.console.write']]] as any[]) {
    const relic = JSON.stringify({ ...base, target:'windows-x86_64-msvc', profile:'stellar-lab-v0', abi:'stellar-win64-v0.1', effects:[], [field]:value });
    const manifest = makePackage(`bad-relic-${field}`, { 'app.stellar':fn('app','import bad.relic / value_of ·\n') }, relic);
    const result = run(['check-package', manifest, '--diagnostic-format', 'json']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /S4005|S4003/);
  }
});

test('refuses incompatible package/RELIC versions and non-ABI export types', () => {
  const packageVersion = makePackage('bad-package-version', { 'main.stellar':fn('main') });
  const packageManifest = JSON.parse(readFileSync(packageVersion, 'utf8')); packageManifest.version='1.0.0'; writeFileSync(packageVersion, JSON.stringify(packageManifest), 'utf8');
  let result=run(['check-package',packageVersion,'--diagnostic-format','json']); assert.equal(result.status,1); assert.match(result.stderr,/S4005/);
  const badRelic = JSON.stringify({ schema:'stellar.relic-interface/v0.1',name:'bad.relic',version:'0.2.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',abi:'stellar-win64-v0.1',exports:[{name:'value_of',parameters:['i32'],result:'i32'}],effects:[],imports:[] });
  result=run(['check-package',makePackage('bad-relic-version',{'app.stellar':fn('app','import bad.relic / value_of ·\n')},badRelic),'--diagnostic-format','json']); assert.equal(result.status,1); assert.match(result.stderr,/S4005/);
  const badAbiType=makePackage('bad-abi-type',{'main.stellar':'module main ·\nexport expose ·\nstruct Local ( value / i32 ) ·\nfunction expose ( value / Local ) / Result ( i32 ) ( return ok ( 1 ) · ) ·\n'});
  result=run(['check-package',badAbiType,'--diagnostic-format','json']); assert.equal(result.status,1); assert.match(result.stderr,/S4005/);
});

test('refuses module path traversal and resolved symlink/junction escape', () => {
  const traversal = makePackage('traversal', { 'main.stellar':fn('main') });
  const manifest = JSON.parse(readFileSync(traversal, 'utf8')); manifest.modules[0] = '../escape.stellar'; manifest.entry = '../escape.stellar'; writeFileSync(traversal, JSON.stringify(manifest), 'utf8');
  const escaped = run(['check-package', traversal, '--diagnostic-format', 'json']); assert.equal(escaped.status,1); assert.match(escaped.stderr,/S5002/);

  const outside = join(scratch, 'outside'); mkdirSync(outside, { recursive:true }); writeFileSync(join(outside,'outside.stellar'), fn('outside'), 'utf8');
  const root = join(scratch, 'symlink-package'); mkdirSync(root, { recursive:true }); symlinkSync(outside, join(root,'linked'), 'junction');
  writeFileSync(join(root,'stellar.package.json'), JSON.stringify({schema:'stellar.package/v0.1',name:'symlink',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'linked/outside.stellar',modules:['linked/outside.stellar'],relics:[],capabilities:[]}), 'utf8');
  const symlinked = run(['check-package', join(root,'stellar.package.json'), '--diagnostic-format','json']); assert.equal(symlinked.status,1); assert.match(symlinked.stderr,/S5002/);
});
