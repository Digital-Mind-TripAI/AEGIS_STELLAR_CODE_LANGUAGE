import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test, { after, before } from 'node:test';
import { parseStellar } from '../../../../src/stellar/parser.js';
import { executeStellar } from '../../../../src/stellar/runtime.js';

const root=resolve('native/stellar/v0_1');
const scratch=mkdtempSync(join(tmpdir(),'stellar-v01-t6-'));
const compiler=join(scratch,'compiler','stellar.exe');
const stdlib=join(root,'stdlib');
const sha=(value:string|Buffer)=>`sha256:${createHash('sha256').update(value).digest('hex')}`;
before(()=>execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',join(root,'tools/build-cli.ps1'),'-Output',compiler],{cwd:resolve('.'),stdio:'pipe'}));
after(()=>rmSync(scratch,{recursive:true,force:true}));
function run(args:string[],options:{timeout?:number,maxBuffer?:number}={}){return spawnSync(compiler,args,{cwd:resolve('.'),encoding:'utf8',timeout:options.timeout??5_000,maxBuffer:options.maxBuffer??4*1024*1024});}
function packageAt(name:string,modules:Record<string,string>,relics:Record<string,string>={}){const dir=join(scratch,name);mkdirSync(dir,{recursive:true});for(const [path,source] of Object.entries(modules)){mkdirSync(dirname(join(dir,path)),{recursive:true});writeFileSync(join(dir,path),source,'utf8');}for(const [path,body] of Object.entries(relics)){mkdirSync(dirname(join(dir,path)),{recursive:true});writeFileSync(join(dir,path),body,'utf8');}const manifest=join(dir,'stellar.package.json');writeFileSync(manifest,JSON.stringify({schema:'stellar.package/v0.1',name,version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:Object.keys(modules)[0],modules:Object.keys(modules),relics:Object.keys(relics),capabilities:[]}),'utf8');return{dir,manifest};}
const simple=(module:string,value=1)=>`module ${module} ·\nexport value ·\nfunction value ( ) / Result ( i32 ) ( return ok ( ${value} ) · ) ·\n`;

test('grammar, type, layout, ABI and lowering inspection matches reviewed golden hashes',()=>{
  const golden=JSON.parse(readFileSync(join(root,'tests/golden/t6-golden-hashes.json'),'utf8'));
  for(const entry of golden.entries){const result=run(['inspect',resolve(entry.target),'--view',entry.view]);assert.equal(result.status,0,result.stderr);assert.equal(sha(result.stdout),entry.sha256,`${entry.family}:${entry.view}`);}
});

test('Reference Preview WAVE grammar remains deterministic against its parser and oracle',async()=>{
  const samples=[
    {source:'element bridge / SignalBridge ( gain: 1 ) ·\nflow bridge ~ Scale ( factor: 2 ) ·\n',signal:[1,2],output:[2,4]},
    {source:'element bridge / SignalBridge ( gain: 2 ) ·\nflow bridge ~ Offset ( amount: -1 ) ·\n',signal:[2,4],output:[1,3]},
    {source:'element bridge / SignalBridge ( gain: 1 ) ·\nflow bridge ~ Scale ( factor: 3 ) ~ Offset ( amount: 2 ) ·\n',signal:[-1,0,2],output:[-1,2,8]},
  ];
  for(const sample of samples){const first=await parseStellar(sample.source),second=await parseStellar(sample.source);assert.equal(first.hash,second.hash);const result=await executeStellar(first,{signal:sample.signal});assert.deepEqual(result.preview.output,sample.output);assert.equal(result.homeostasis.status,'NOT_EVALUATED');}
});

test('native CLI keeps the Reference Preview WAVE grammar outside the typed v0.1 boundary',()=>{
  const file=join(scratch,'reference-preview-wave.stellar');
  writeFileSync(file,'element bridge / SignalBridge ( gain: 1 ) ·\nflow bridge ~ Scale ( factor: 2 ) ·\n','utf8');
  const result=run(['check',file]);
  assert.equal(result.status,1);
  assert.match(result.stderr,/S1009/);
});

test('fixed-seed bounded property corpus is byte-deterministic and never times out',()=>{
  let state=0x5e11a7;const next=()=>state=(Math.imul(state,1664525)+1013904223)>>>0;
  for(let index=0;index<72;index++){const a=(next()%200)-100,b=(next()%200)-100;const valid=index%4!==0;const text=valid?`function f${index} ( value / i32 ) / Result ( i32 ) ( return ok ( ${index%3===0?'wrapping_add':'add'} ( value, ${a} ) ) · ) ·\n`:`function f${index} ( value / i32 ) / Result ( i32 ) ( return ok ( add ( value, ${b} ) ) ) ·\n`;const path=join(scratch,`seed-${index}.stellar`);writeFileSync(path,text,'utf8');const first=run(['check',path,'--diagnostic-format','json'],{timeout:2_000}),second=run(['check',path,'--diagnostic-format','json'],{timeout:2_000});assert.notEqual(first.error?.code,'ETIMEDOUT');assert.equal(second.status,first.status);assert.equal(second.stdout,first.stdout);assert.equal(second.stderr,first.stderr);assert.equal(first.status,valid?0:1);}
});

test('package/module/RELIC corpus refuses cycles, symbol conflicts, ABI/target/effect tamper and escapes',()=>{
  const cycle=packageAt('attack-cycle',{'a.stellar':'module a ·\nimport b / value ·\nexport a_value ·\nfunction a_value ( ) / Result ( i32 ) ( return ok ( value ( ) ) · ) ·\n','b.stellar':'module b ·\nimport a / a_value ·\nexport value ·\nfunction value ( ) / Result ( i32 ) ( return ok ( a_value ( ) ) · ) ·\n'});assert.match(run(['check-package',cycle.manifest]).stderr,/S4004/);
  const duplicate=packageAt('attack-symbol',{'a.stellar':'module a ·\nexport value ·\nexport value ·\nfunction value ( ) / Result ( i32 ) ( return ok ( 1 ) · ) ·\n'});assert.match(run(['check-package',duplicate.manifest]).stderr,/S4002/);
  const relicBase={schema:'stellar.relic-interface/v0.1',name:'host.bad',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',abi:'stellar-win64-v0.1',exports:[{name:'host_value',parameters:[],result:'i32'}],effects:[],imports:[]};
  for(const [field,value,code] of [['target','linux-x86_64','S4005'],['abi','c','S4005'],['effects',['windows.console.write'],'S4003'],['imports',['WriteFile'],'S4003']] as const){const relic=JSON.stringify({...relicBase,[field]:value});const pkg=packageAt(`attack-relic-${field}`,{'app.stellar':'module app ·\nimport host.bad / host_value ·\nexport main ·\nfunction main ( ) / Result ( i32 ) ( return ok ( host_value ( ) ) · ) ·\n'},{'relics/host.bad.json':relic});const result=run(['check-package',pkg.manifest]);assert.match(result.stderr,new RegExp(code));}
  const traversal=packageAt('attack-traversal',{'main.stellar':simple('main')});const manifest=JSON.parse(readFileSync(traversal.manifest,'utf8'));manifest.entry='../outside.stellar';manifest.modules=['../outside.stellar'];writeFileSync(traversal.manifest,JSON.stringify(manifest),'utf8');assert.match(run(['check-package',traversal.manifest]).stderr,/S5002/);
  const outside=join(scratch,'junction-outside');mkdirSync(outside);writeFileSync(join(outside,'outside.stellar'),simple('outside'),'utf8');const junction=join(scratch,'attack-junction');mkdirSync(junction);symlinkSync(outside,join(junction,'linked'),'junction');writeFileSync(join(junction,'stellar.package.json'),JSON.stringify({schema:'stellar.package/v0.1',name:'junction',version:'0.1.0',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',entry:'linked/outside.stellar',modules:['linked/outside.stellar'],relics:[],capabilities:[]}),'utf8');assert.match(run(['check-package',join(junction,'stellar.package.json')]).stderr,/S5002/);
});

test('compiler arguments, source bounds and output response bounds fail closed',()=>{
  const marker=join(scratch,'injection-marker');const attempted=run(['check',`missing.stellar;New-Item -ItemType File -Path ${marker}`]);assert.notEqual(attempted.status,0);assert.equal(existsSync(marker),false);
  const huge=join(scratch,'huge.stellar');writeFileSync(huge,'x'.repeat(262145),'utf8');let result=run(['inspect',huge,'--view','tokens'],{timeout:2_000,maxBuffer:1024*1024});assert.equal(result.status,1);assert.match(result.stderr,/S0001/);assert.notEqual(result.error?.code,'ETIMEDOUT');
  result=run(['build','x','--output','y','--stdlib','z','--flag','@evil.rsp']);assert.equal(result.status,2);assert.match(result.stderr,/usage:/i);assert.ok(result.stdout.length+result.stderr.length<64*1024);
});

test('malformed Unicode, numeric, JSON and schema inputs have coded bounded refusals',()=>{
  const cases:[string,Buffer|string,RegExp][]=[['utf8',Buffer.from([0xed,0xa0,0x80]),/S0003/],['nul',Buffer.from('function x\0'),/S0002/],['numeric','function x ( ) / Result ( i32 ) ( return ok ( 999999999999999999999999 ) · ) ·\n',/S2007/]];for(const [name,body,expected] of cases){const path=join(scratch,`${name}.stellar`);writeFileSync(path,body);const result=run(['check',path]);assert.equal(result.status,1);assert.match(result.stderr,expected);}
  for(const [name,body] of [['json','{"schema":'],['schema',JSON.stringify({schema:'unknown',name:'x'})]]){const path=join(scratch,`${name}.package.json`);writeFileSync(path,body,'utf8');const result=run(['inspect-manifest',path,'--diagnostic-format','json']);assert.equal(result.status,1);assert.match(result.stderr,/S5001/);assert.ok(JSON.parse(result.stderr).help);}
});

test('build confines output and removes partial evidence after injected integrity faults',()=>{
  const source=resolve('native/stellar/v0_1/tests/fixtures/tranche2/chain');const pkg=join(scratch,'cleanup-package');cpSync(source,pkg,{recursive:true});const manifest=join(pkg,'stellar.package.json');assert.equal(run(['inspect-manifest',manifest,'--write-lock']).status,0);assert.equal(run(['check-package',manifest,'--write-dependency-lock']).status,0);
  const contained=join(pkg,'nested-output');let result=run(['build',manifest,'--output',contained,'--stdlib',stdlib],{timeout:60_000,maxBuffer:8*1024*1024});assert.equal(result.status,1);assert.match(result.stderr,/S6003/);assert.equal(existsSync(contained),false);
  writeFileSync(join(pkg,'math.stellar'),`${readFileSync(join(pkg,'math.stellar'),'utf8')}\n`,'utf8');const partial=join(scratch,'fault-cleanup');result=run(['build',manifest,'--output',partial,'--stdlib',stdlib],{timeout:60_000,maxBuffer:8*1024*1024});assert.equal(result.status,1);assert.match(result.stderr,/S5003/);assert.equal(existsSync(partial),false);
});

test('reproducibility matrix and release gate preserve raw/normalized truth and closed execution',()=>{
  const matrix=readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_REPRODUCIBILITY_MATRIX.md'),'utf8');assert.match(matrix,/Raw COFF object bytes/i);assert.match(matrix,/Normalized symbol, relocation, and disassembly evidence/i);assert.match(matrix,/toolchain-qualified/i);assert.match(matrix,/not authorization/i);
  const generator=readFileSync(join(root,'tools/release-acceptance.mjs'),'utf8');assert.doesNotMatch(generator,/\b(run|LoadLibrary|CreateProcess)\s*\(/);assert.match(generator,/nativeCodeExecuted:\s*false/);assert.match(generator,/T0.*T6/s);JSON.parse(readFileSync(join(root,'schemas/stellar-release-acceptance-v0.1.schema.json'),'utf8'));
  const bad=join(scratch,'bad-gates.json');writeFileSync(bad,JSON.stringify({gates:[{name:'forced-failure',passed:false}]}),'utf8');const report=join(scratch,'release.json');const failed=spawnSync(process.execPath,[join(root,'tools/release-acceptance.mjs'),'--assess',bad,'--report',report],{cwd:resolve('.'),encoding:'utf8'});assert.equal(failed.status,1);assert.equal(JSON.parse(readFileSync(report,'utf8')).status,'fail');
});
