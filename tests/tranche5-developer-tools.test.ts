import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root=resolve('native/stellar/v0_1');const scratch=mkdtempSync(join(tmpdir(),'stellar-v01-t5-'));const compiler=join(scratch,'compiler','stellar.exe');const stdlib=join(root,'stdlib');let serial=0;
before(()=>execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',join(root,'tools/build-cli.ps1'),'-Output',compiler],{cwd:resolve('.'),stdio:'pipe'}));
after(()=>rmSync(scratch,{recursive:true,force:true}));
function run(args:string[]){return spawnSync(compiler,args,{cwd:resolve('.'),encoding:'utf8',maxBuffer:16*1024*1024});}
function prepare(fixture:string,name:string){const directory=join(scratch,name);cpSync(fixture,directory,{recursive:true});const manifest=join(directory,'stellar.package.json');for(const args of [['inspect-manifest',manifest,'--write-lock'],['check-package',manifest,'--write-dependency-lock']]){const result=run(args);assert.equal(result.status,0,result.stderr);}return{directory,manifest};}
function build(manifest:string){const output=join(scratch,`native-build-${serial++}`);const result=run(['build',manifest,'--output',output,'--stdlib',stdlib]);assert.equal(result.status,0,result.stderr);return output;}

test('stable command surface explicitly refuses run while source/package developer commands remain available',()=>{
  assert.equal(run(['version']).status,0);const refusal=run(['run','untrusted.stellar']);assert.equal(refusal.status,1);assert.match(refusal.stderr,/S7001/);const json=run(['run','untrusted.stellar','--diagnostic-format','json']);assert.equal(json.status,1);const diagnostic=JSON.parse(json.stderr);assert.equal(diagnostic.code,'S7001');assert.equal(diagnostic.stage,'developer-tooling-security');assert.deepEqual(diagnostic.secondarySpans,[]);
});

test('diagnostic JSON carries stable stage, primary span, secondary spans and help across compiler layers',()=>{
  const lexical=join(scratch,'lexical.stellar');writeFileSync(lexical,'function @','utf8');let result=run(['check',lexical,'--diagnostic-format','json']);let diagnostic=JSON.parse(result.stderr);assert.equal(diagnostic.stage,'lex-parse');assert.deepEqual(diagnostic.primarySpan,diagnostic.span);assert.ok(diagnostic.help);
  const duplicate=join(scratch,'duplicate-module');mkdirSync(duplicate);writeFileSync(join(duplicate,'a.stellar'),'module same ·\nexport a ·\nfunction a ( ) / Result ( i32 ) ( return ok ( 1 ) · ) ·\n','utf8');writeFileSync(join(duplicate,'b.stellar'),'module same ·\nexport b ·\nfunction b ( ) / Result ( i32 ) ( return ok ( 2 ) · ) ·\n','utf8');const manifest=join(duplicate,'stellar.package.json');writeFileSync(manifest,JSON.stringify({schema:'stellar.package/v0.1',name:'duplicate',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'a.stellar',modules:['a.stellar','b.stellar'],relics:[],capabilities:[]}),'utf8');result=run(['check-package',manifest,'--diagnostic-format','json']);diagnostic=JSON.parse(result.stderr);assert.equal(diagnostic.code,'S4001');assert.equal(diagnostic.stage,'module-relic');assert.equal(diagnostic.secondarySpans.length,1);assert.match(diagnostic.secondarySpans[0].label,/first declaration/i);
  result=run(['inspect',lexical,'--view','not-a-view','--diagnostic-format','json']);assert.equal(result.status,1);diagnostic=JSON.parse(result.stderr);assert.equal(diagnostic.code,'S7002');assert.equal(diagnostic.stage,'developer-tooling-security');
  const f64=join(scratch,'diagnostic-f64');mkdirSync(f64);writeFileSync(join(f64,'app.stellar'),'module app ·\nexport main ·\nfunction main ( value / f64 ) / Result ( f64 ) ( return ok ( value ) · ) ·\n','utf8');const f64Manifest=join(f64,'stellar.package.json');writeFileSync(f64Manifest,JSON.stringify({schema:'stellar.package/v0.1',name:'diagnostic-f64',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'app.stellar',modules:['app.stellar'],relics:[],capabilities:[]}),'utf8');result=run(['check-package',f64Manifest,'--write-dependency-lock']);assert.equal(result.status,0,result.stderr);const failedOutput=join(scratch,'diagnostic-f64-build');result=run(['build',f64Manifest,'--output',failedOutput,'--stdlib',stdlib,'--diagnostic-format','json']);assert.equal(result.status,1);diagnostic=JSON.parse(result.stderr);assert.equal(diagnostic.code,'S6002');assert.equal(diagnostic.stage,'lower-link');assert.deepEqual(diagnostic.secondarySpans,[]);
});

test('canonical formatter roundtrips and is idempotent across typed memory/control and module grammar',()=>{
  const fixtures=[resolve('native/stellar/v0_1/tests/fixtures/tranche1/control-calls.stellar'),resolve('native/stellar/v0_1/tests/fixtures/tranche1/memory-layout.stellar'),resolve('native/stellar/v0_1/tests/fixtures/tranche4/control/control.stellar')];
  for(const [index,fixture] of fixtures.entries()){const first=run(['fmt',fixture]);assert.equal(first.status,0,first.stderr);const canonical=join(scratch,`formatted-${index}.stellar`);writeFileSync(canonical,first.stdout,'utf8');const second=run(['fmt',canonical]);assert.equal(second.status,0,second.stderr);assert.equal(second.stdout,first.stdout);assert.equal(run(['fmt',canonical,'--check']).status,0);}
});

test('inspect exposes deterministic source, package, and native build processing layers',()=>{
  const typed=resolve('native/stellar/v0_1/tests/fixtures/tranche1/control-calls.stellar');for(const view of ['tokens','ast','hir','mir','layout','effects','hashes']){const first=run(['inspect',typed,'--view',view]);const second=run(['inspect',typed,'--view',view]);assert.equal(first.status,0,first.stderr);assert.equal(second.stdout,first.stdout);const parsed=JSON.parse(first.stdout);assert.equal(parsed.view,view);assert.equal(parsed.executionEnabled,false);}
  const prepared=prepare(resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain'),'inspect-package');for(const view of ['module-graph','symbols','effects','hashes']){const inspected=run(['inspect',prepared.manifest,'--view',view]);assert.equal(inspected.status,0,inspected.stderr);assert.equal(JSON.parse(inspected.stdout).targetKind,'package');}
  const output=build(prepared.manifest);for(const view of ['relocations','assembly','machine-bytes','effects','hashes']){const inspected=run(['inspect',output,'--view',view]);assert.equal(inspected.status,0,inspected.stderr);const parsed=JSON.parse(inspected.stdout);assert.equal(parsed.targetKind,'native-build');assert.equal(parsed.executionEnabled,false);assert.ok(parsed.document);}
});

test('test command runs deterministic source/module/lowering conformance without native execution',()=>{
  const prepared=prepare(resolve('native/stellar/v0_1/tests/fixtures/tranche4/control'),'conformance');const first=run(['test',prepared.manifest]);const second=run(['test',prepared.manifest]);assert.equal(first.status,0,first.stderr);assert.equal(second.stdout,first.stdout);const report=JSON.parse(first.stdout);assert.equal(report.status,'pass');assert.equal(report.nativeCodeExecuted,false);assert.equal(report.executionEnabled,false);assert.ok(report.checks.includes('source-map-trace'));assert.match(report.nativePlanHash,/^sha256:[0-9a-f]{64}$/);
});

test('package emits a deterministic canonical source/RELIC/schema/provenance bundle and refuses tamper',()=>{
  const prepared=prepare(resolve('native/stellar/v0_1/tests/fixtures/tranche4/stdlib-call'),'bundle');const first=join(scratch,'first.stellar-bundle.json'),second=join(scratch,'second.stellar-bundle.json');let result=run(['package',prepared.manifest,'--output',first]);assert.equal(result.status,0,result.stderr);result=run(['package',prepared.manifest,'--output',second]);assert.equal(result.status,0,result.stderr);assert.equal(readFileSync(first,'utf8'),readFileSync(second,'utf8'));const bundle=JSON.parse(readFileSync(first,'utf8'));assert.equal(bundle.payload.schema,'stellar.bundle/v0.1');assert.equal(bundle.payload.executionEnabled,false);assert.equal(bundle.payload.provenance.nativeExecuted,false);assert.ok(bundle.payload.modules.length>=2);assert.ok(bundle.payload.relics.length>=1);assert.ok(bundle.payload.schemas.length>=10);result=run(['package',prepared.manifest,'--verify',first]);assert.equal(result.status,0,result.stderr);writeFileSync(first,`${readFileSync(first,'utf8')} `,'utf8');result=run(['package',prepared.manifest,'--verify',first]);assert.equal(result.status,1);assert.match(result.stderr,/S7004/);
});

test('per-module source maps cover native symbols and spans without user-code execution',()=>{
  const prepared=prepare(resolve('native/stellar/v0_1/tests/fixtures/tranche4/control'),'trace');const output=build(prepared.manifest);for(const name of ['617070','636f6e74726f6c']){const trace=JSON.parse(readFileSync(join(output,'assembly',`${name}.trace.json`),'utf8'));assert.ok(trace.sourceMap.length>=1);for(const mapping of trace.sourceMap){assert.match(mapping.symbol,/^stellar_v01_/);assert.ok(mapping.span.end.offset>mapping.span.start.offset);}assert.deepEqual(trace.effects,[]);assert.deepEqual(trace.imports,[]);}
});

test('published tooling schemas and contract retain the closed execution gate',()=>{
  for(const name of ['stellar-inspect-v0.1.schema.json','stellar-conformance-test-v0.1.schema.json','stellar-bundle-v0.1.schema.json'])JSON.parse(readFileSync(join(root,'schemas',name),'utf8'));const contract=readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_DEVELOPER_TOOLING.md'),'utf8');assert.match(contract,/stellar run.*coded refusal `S7001`/i);assert.match(contract,/Checksum or bundle integrity is not authorization/i);assert.match(contract,/Custodian\/Steward Relation Contract/i);assert.match(contract,/OS-enforced process-isolation gate remains closed/i);
});
