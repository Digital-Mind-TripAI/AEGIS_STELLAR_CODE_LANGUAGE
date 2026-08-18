import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after } from 'node:test';

const root = resolve('native/stellar/v0_1');
const stdlib = join(root, 'stdlib');
const builder = join(root, 'tools/build-stdlib.ps1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-stdlib-'));
after(() => rmSync(scratch, { recursive: true, force: true }));

function build(stdlibRoot = stdlib, extra: string[] = []) {
  const output = mkdtempSync(join(scratch, 'build-'));
  const result = spawnSync('powershell.exe', ['-NoProfile','-ExecutionPolicy','Bypass','-File',builder,'-StdlibRoot',stdlibRoot,'-OutputDirectory',output,...extra], { cwd: resolve('.'), encoding:'utf8' });
  return { result, output, report: result.status===0 ? JSON.parse(readFileSync(join(output,'stdlib-verification.json'),'utf8')) : undefined };
}

test('three pure standard RELICs emit inspectable zero-import COFF objects', () => {
  const { result, report } = build();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(Object.keys(report.relics), ['core.checked','core.memory','core.result']);
  for (const relic of Object.values(report.relics) as any[]) {
    assert.equal(relic.target, 'windows-x86_64-msvc');
    assert.equal(relic.abi, 'stellar-win64-v0.1');
    assert.deepEqual(relic.effects, []);
    assert.deepEqual(relic.undefinedExternalSymbols, []);
    for (const field of ['sourceHash','interfaceHash','objectHash','symbolsHash','disassemblyHash','evidenceHash']) assert.match(relic[field], /^sha256:[a-f0-9]{64}$/, field);
    assert.ok(relic.definedSymbols.length >= 3);
    assert.equal(relic.objectEmitted, true);
    assert.equal(relic.executableLinked, false);
  }
});

test('checked/wrapping, bounded memory, and Result disassembly expose the intended machine operations', () => {
  const { result, report } = build(); assert.equal(result.status,0,result.stderr);
  assert.match(report.relics['core.checked'].disassembly, /\bjo\b/i);
  assert.match(report.relics['core.checked'].disassembly, /\bimul\b/i);
  assert.match(report.relics['core.memory'].disassembly, /\bcmp\b/i);
  assert.match(report.relics['core.memory'].disassembly, /\bja\b|\bjae\b/i);
  assert.match(report.relics['core.result'].disassembly, /\bset(?:e|z)\b/i);
});

test('reproducibility report states raw-object truth and deterministic normalized evidence', () => {
  const { result, report } = build(); assert.equal(result.status,0,result.stderr);
  for (const relic of Object.values(report.relics) as any[]) {
    assert.equal(typeof relic.reproducibility.objectByteIdentical, 'boolean');
    assert.equal(relic.reproducibility.normalizedEvidenceIdentical, true);
    assert.match(relic.reproducibility.note, /toolchain|object path|byte-identical/i);
  }
  assert.match(report.toolchain.assemblerVersion, /^\d+/);
  assert.match(report.toolchainHash, /^sha256:[a-f0-9]{64}$/);
});

test('ConsoleWrite remains a separate unauthorised, uncompiled capability contract', () => {
  const { result, report } = build(); assert.equal(result.status,0,result.stderr);
  assert.deepEqual(report.consoleWrite, {
    name:'windows.console', capability:'windows.console.write', allowedImports:[{dll:'KERNEL32.dll',symbols:['WriteFile']}],
    relationContractRequired:true, custodianStewardAuthenticationRequired:true, osProcessIsolationRequired:true,
    authorized:false, compiled:false, executionEnabled:false,
  });
  assert.equal(report.assembledSources.includes('sources/windows.console.asm'), false);
});

test('stdlib canonical lock binds manifest, interfaces, sources, objects and toolchain and refuses tamper', () => {
  const copy = join(scratch,'stdlib-copy'); cpSync(stdlib,copy,{recursive:true});
  const first=build(copy); assert.equal(first.result.status,0,first.result.stderr);
  const lock=join(first.output,'stellar.stdlib.lock.json');
  const verified=build(copy,['-VerifyLock',lock]); assert.equal(verified.result.status,0,verified.result.stderr);
  const source=join(copy,'sources/core.result.asm'); writeFileSync(source,`${readFileSync(source,'utf8')}\n`,'utf8');
  const tampered=build(copy,['-VerifyLock',lock]); assert.notEqual(tampered.result.status,0); assert.match(tampered.result.stderr,/integrity|lock|tamper/i);
});

test('refuses duplicate/colliding symbols and interface/source identity tamper before accepting evidence', () => {
  const copy = join(scratch,'collision-copy'); cpSync(stdlib,copy,{recursive:true});
  const checked=join(copy,'interfaces/core.checked.relic.json'); const parsed=JSON.parse(readFileSync(checked,'utf8')); parsed.exports.push(parsed.exports[0]); writeFileSync(checked,JSON.stringify(parsed),'utf8');
  let attempt=build(copy); assert.notEqual(attempt.result.status,0); assert.match(attempt.result.stderr,/duplicate|collision|symbol/i);
  rmSync(copy,{recursive:true,force:true}); cpSync(stdlib,copy,{recursive:true});
  writeFileSync(join(copy,'sources/core.memory.asm'),readFileSync(join(copy,'sources/core.memory.asm'),'utf8').replace('PUBLIC stellar_','PUBLIC unexpected_symbol\nPUBLIC stellar_'),'utf8');
  attempt=build(copy); assert.notEqual(attempt.result.status,0); assert.match(attempt.result.stderr,/symbol|interface|mismatch/i);
  rmSync(copy,{recursive:true,force:true}); cpSync(stdlib,copy,{recursive:true});
  const consoleDescriptor=join(copy,'capabilities/windows.console.relic.json'); const capability=JSON.parse(readFileSync(consoleDescriptor,'utf8')); capability.allowedImports[0].symbols.push('CreateProcessW'); writeFileSync(consoleDescriptor,JSON.stringify(capability),'utf8');
  attempt=build(copy); assert.notEqual(attempt.result.status,0); assert.match(attempt.result.stderr,/ConsoleWrite import allowlist mismatch/i);
});

test('three independent package callers type-check against checked, memory, and Result interfaces', () => {
  const compilerOutput=mkdtempSync(join(scratch,'compiler-')); const executable=join(compilerOutput,'stellar.exe');
  execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',join(root,'tools/build-cli.ps1'),'-Output',executable],{cwd:resolve('.'),stdio:'pipe'});
  const callers = [
    ['core.checked','checked_add_i32','function main ( a / i32, b / i32 ) / Result ( i32 ) ( return ok ( try_value ( checked_add_i32 ( a, b ) ) ) · ) ·'],
    ['core.memory','equal_u8','function main ( a / slice ( u32, 65536 ), b / slice ( u32, 65536 ) ) / Result ( bool ) ( return ok ( try_value ( equal_u8 ( a, b ) ) ) · ) ·'],
    ['core.result','status_is_ok','function main ( status / i32 ) / Result ( bool ) ( return ok ( try_value ( status_is_ok ( status ) ) ) · ) ·'],
  ];
  for (const [provider,symbol,body] of callers) {
    const dir=join(scratch,`caller-${symbol}`); mkdirSync(join(dir,'relics'),{recursive:true});
    cpSync(join(stdlib,'interfaces',`${provider}.relic.json`),join(dir,'relics',`${provider}.json`));
    writeFileSync(join(dir,'app.stellar'),`module app ·\nimport ${provider} / ${symbol} ·\nexport main ·\n${body}\n`,'utf8');
    writeFileSync(join(dir,'stellar.package.json'),JSON.stringify({schema:'stellar.package/v0.1',name:`caller-${symbol}`,version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'app.stellar',modules:['app.stellar'],relics:[`relics/${provider}.json`],capabilities:[]}),'utf8');
    const checked=spawnSync(executable,['check-package',join(dir,'stellar.package.json')],{encoding:'utf8'}); assert.equal(checked.status,0,`${symbol}: ${checked.stderr}`);
  }
});

test('Tranche 3 contract preserves the zero-effect and mandatory authorization boundaries', () => {
  const contract = readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_CORE_STDLIB.md'), 'utf8');
  const builder = readFileSync(resolve('native/stellar/v0_1/tools/build-stdlib.ps1'), 'utf8');
  const schemas = [
    'stellar-stdlib-v0.1.schema.json',
    'stellar-stdlib-lock-v0.1.schema.json',
    'stellar-capability-relic-v0.1.schema.json',
  ];
  for (const schema of schemas) JSON.parse(readFileSync(resolve('native/stellar/v0_1/schemas', schema), 'utf8'));
  assert.match(contract, /allocate no heap, import no OS symbol, declare no effect/i);
  assert.match(contract, /authenticated Custodian\/Steward-issued capability contracts/i);
  assert.match(contract, /OS-enforced native process isolation/i);
  assert.doesNotMatch(builder, /\blink(?:\.exe)?\b|Start-Process/i);
});
