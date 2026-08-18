import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root=resolve('native/stellar/v0_1');
const stdlib=join(root,'stdlib');
const scratch=mkdtempSync(join(tmpdir(),'stellar-v01-t4-'));
const compiler=join(scratch,'compiler','stellar.exe');
let outputNumber=0;
before(()=>execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',join(root,'tools/build-cli.ps1'),'-Output',compiler],{cwd:resolve('.'),stdio:'pipe'}));
after(()=>rmSync(scratch,{recursive:true,force:true}));

function copyPackage(source:string,name:string){const target=join(scratch,name);cpSync(source,target,{recursive:true});return target;}
function lockPackage(directory:string){const result=spawnSync(compiler,['check-package',join(directory,'stellar.package.json'),'--write-dependency-lock'],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);}
function buildPackage(directory:string,extra:string[]=[]){const output=join(scratch,`build-${outputNumber++}`);const result=spawnSync(compiler,['build',join(directory,'stellar.package.json'),'--output',output,'--stdlib',stdlib,...extra],{encoding:'utf8'});return{result,output,report:result.status===0?JSON.parse(readFileSync(join(output,'native-build-evidence.json'),'utf8')):undefined,lock:result.status===0?join(output,'stellar.native.build.lock.json'):undefined};}

test('at least three structurally distinct multi-module packages lower, assemble, link and inspect without execution',()=>{
  const fixtures=[
    [resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),2],
    [resolve('native/stellar/v0_1/tests/fixtures/tranche2/diamond'),4],
    [resolve('native/stellar/v0_1/tests/fixtures/tranche4/stdlib-call'),2],
    [resolve('native/stellar/v0_1/tests/fixtures/tranche4/control'),2],
  ] as const;
  for(const [fixture,count] of fixtures){const directory=copyPackage(fixture,`positive-${count}-${outputNumber}`);lockPackage(directory);const built=buildPackage(directory);assert.equal(built.result.status,0,built.result.stderr);assert.equal(Object.keys(built.report.modules).length,count);assert.equal(built.report.executionEnabled,false);assert.equal(built.report.loaded,false);assert.equal(built.report.ran,false);assert.deepEqual(built.report.linked.imports,[]);assert.equal(built.report.linked.entryPoint,false);assert.equal(built.report.linked.executed,false);assert.equal(built.report.consoleWrite.compiled,false);for(const module of Object.values(built.report.modules) as any[]){assert.equal(module.objectEmitted,true);assert.equal(module.executableLinked,false);assert.equal(module.normalizedEvidenceIdentical,true);for(const field of ['assemblyHash','symbolsHash','relocationsHash','disassemblyHash','evidenceHash'])assert.match(module[field],/^sha256:[0-9a-f]{64}$/);}}
});

test('generated MASM is operation-derived and records exact cross-module and stdlib calls',()=>{
  const directory=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche4/stdlib-call'),'operation-derived');lockPackage(directory);const built=buildPackage(directory);assert.equal(built.result.status,0,built.result.stderr);const assemblies=join(built.output,'assembly');const texts=['617070','6d617468'].map(name=>readFileSync(join(assemblies,`${name}.asm`),'utf8')).join('\n');assert.match(texts,/\bcall stellar_v01_/i);assert.match(texts,/EXTERN stellar_v01_m636f72652e636865636b6564_/i);assert.match(texts,/test eax, eax/i);assert.doesNotMatch(texts,/WriteFile|ConsoleWrite|KERNEL32/i);
});

test('native build lock is deterministic across output paths and independently verifiable',()=>{
  const directory=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'deterministic');lockPackage(directory);const first=buildPackage(directory);assert.equal(first.result.status,0,first.result.stderr);const second=buildPackage(directory,['--verify-build-lock',first.lock!]);assert.equal(second.result.status,0,second.result.stderr);assert.equal(readFileSync(first.lock!,'utf8'),readFileSync(second.lock!,'utf8'));for(const module of Object.values(second.report.modules) as any[])assert.equal(typeof module.objectByteIdentical,'boolean');
});

test('refuses missing and stale dependency locks and cleans partial output',()=>{
  const missing=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'missing-lock');let built=buildPackage(missing);assert.notEqual(built.result.status,0);assert.match(built.result.stderr,/S5003/);assert.equal(existsSync(built.output),false);
  const stale=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'stale-lock');lockPackage(stale);writeFileSync(join(stale,'math.stellar'),`${readFileSync(join(stale,'math.stellar'),'utf8')}\n`,'utf8');built=buildPackage(stale);assert.notEqual(built.result.status,0);assert.match(built.result.stderr,/S5003|dependency evidence/i);assert.equal(existsSync(built.output),false);
});

test('refuses capabilities, hash-inexact RELIC interfaces and symbol/link conflicts before accepting evidence',()=>{
  const capability=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'capability');const manifestPath=join(capability,'stellar.package.json');const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));manifest.capabilities=['windows.console.write'];writeFileSync(manifestPath,JSON.stringify(manifest),'utf8');let checked=spawnSync(compiler,['check-package',manifestPath,'--write-dependency-lock'],{encoding:'utf8'});assert.notEqual(checked.status,0);assert.match(checked.stderr,/S4003/);
  const relic=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche4/stdlib-call'),'relic-tamper');const relicPath=join(relic,'relics/core.checked.relic.json');writeFileSync(relicPath,`${readFileSync(relicPath,'utf8')}\n`,'utf8');lockPackage(relic);let built=buildPackage(relic);assert.notEqual(built.result.status,0);assert.match(built.result.stderr,/S6004 RELIC interface/i);assert.equal(existsSync(built.output),false);
  const collision=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'symbol-conflict');const app=join(collision,'app.stellar');writeFileSync(app,readFileSync(app,'utf8').replace('export main ·','export main ·\nexport main ·'),'utf8');checked=spawnSync(compiler,['check-package',join(collision,'stellar.package.json'),'--write-dependency-lock'],{encoding:'utf8'});assert.notEqual(checked.status,0);assert.match(checked.stderr,/S4002|duplicate export/i);
});

test('valid check/inspect-only types never silently fall back to native emission',()=>{
  const directory=join(scratch,'f64-refusal');mkdirSync(directory,{recursive:true});writeFileSync(join(directory,'app.stellar'),'module app ·\nexport main ·\nfunction main ( value / f64 ) / Result ( f64 ) ( return ok ( value ) · ) ·\n','utf8');writeFileSync(join(directory,'stellar.package.json'),JSON.stringify({schema:'stellar.package/v0.1',name:'f64-refusal',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'app.stellar',modules:['app.stellar'],relics:[],capabilities:[]}),'utf8');lockPackage(directory);const built=buildPackage(directory);assert.notEqual(built.result.status,0);assert.match(built.result.stderr,/S6002.*native Tranche 4 ABI/i);assert.equal(existsSync(built.output),false);
});

test('build accepts no arbitrary flags and refuses pre-existing output',()=>{
  const directory=copyPackage(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'arguments');lockPackage(directory);let attempted=spawnSync(compiler,['build',join(directory,'stellar.package.json'),'--output',join(scratch,'arbitrary'),'--stdlib',stdlib,'--flag','/ENTRY:evil'],{encoding:'utf8'});assert.equal(attempted.status,2);assert.match(attempted.stderr,/usage:/i);const output=join(scratch,'exists');mkdirSync(output);attempted=spawnSync(compiler,['build',join(directory,'stellar.package.json'),'--output',output,'--stdlib',stdlib],{encoding:'utf8'});assert.notEqual(attempted.status,0);assert.match(attempted.stderr,/S6003.*already exists/i);assert.equal(existsSync(output),true);
});

test('published schemas and contract preserve the non-execution and authorization gates',()=>{
  for(const name of ['stellar-native-build-plan-v0.1.schema.json','stellar-native-build-lock-v0.1.schema.json','stellar-native-build-evidence-v0.1.schema.json'])JSON.parse(readFileSync(join(root,'schemas',name),'utf8'));
  const contract=readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_NATIVE_BUILD_BOUNDARY.md'),'utf8');const cli=readFileSync(join(root,'src/cli.cpp'),'utf8');const driver=readFileSync(join(root,'tools/build-package.ps1'),'utf8');
  assert.match(contract,/never loads or executes/i);assert.match(contract,/checksum integrity is not authorization/i);assert.match(contract,/authenticated Custodian\/Steward-issued Relation Contracts/i);assert.match(contract,/OS-enforced process isolation/i);assert.doesNotMatch(cli,/\bLoadLibrary|CreateProcess/i);assert.doesNotMatch(driver,/Start-Process|Invoke-Expression|\biex\b/i);assert.match(driver,/\/noentry/i);assert.match(driver,/\/nodefaultlib/i);
});
