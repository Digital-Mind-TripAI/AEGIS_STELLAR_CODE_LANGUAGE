import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const toolRoot=dirname(fileURLToPath(import.meta.url));
const stellarRoot=resolve(toolRoot,'..');
const repositoryRoot=resolve(stellarRoot,'../../..');
const suites=[
  'native/stellar/v0_1/tests/contract.test.ts',
  'native/stellar/v0_1/tests/stellar-v0.1-cli.test.ts',
  'native/stellar/v0_1/tests/tranche1-language.test.ts',
  'native/stellar/v0_1/tests/tranche2-packages.test.ts',
  'native/stellar/v0_1/tests/tranche3-stdlib.test.ts',
  'native/stellar/v0_1/tests/tranche4-native-build.test.ts',
  'native/stellar/v0_1/tests/tranche5-developer-tools.test.ts',
  'native/stellar/v0_1/tests/tranche6-conformance-security.test.ts',
  'native/stellar/tests/native-vertical-slice.test.ts',
  'native/stellar/tests/phase-c-native-core.test.ts',
];
function usage(){process.stderr.write('usage: node release-acceptance.mjs --report NEW_FILE [--assess GATE_JSON]\n');process.exit(2);}
let reportPath='',assessmentPath='';for(let index=2;index<process.argv.length;index+=2){const key=process.argv[index],value=process.argv[index+1];if(!value)usage();if(key==='--report')reportPath=value;else if(key==='--assess')assessmentPath=value;else usage();}
if(!reportPath||existsSync(reportPath))usage();
function readBounded(path,limit=1024*1024){const bytes=readFileSync(path);if(bytes.length>limit)throw new Error(`bounded input exceeded: ${path}`);return bytes.toString('utf8');}
function binaryArtifacts(path){const found=[];for(const entry of readdirSync(path,{withFileTypes:true})){const child=resolve(path,entry.name);if(entry.isDirectory())found.push(...binaryArtifacts(child));else if(['.obj','.exe','.dll','.pdb'].includes(extname(entry.name).toLowerCase()))found.push(child);}return found;}
let gates=[];
if(assessmentPath){const input=JSON.parse(readBounded(resolve(assessmentPath)));if(!Array.isArray(input.gates)||input.gates.length===0||input.gates.length>64)throw new Error('assessment requires 1..64 gates');gates=input.gates.map((gate)=>({name:String(gate.name),passed:gate.passed===true,evidence:String(gate.evidence??'supplied assessment')}));gates.push({name:'assessment-is-not-release-evidence',passed:false,evidence:'only the fixed T0-T6 plus legacy corpus can produce a passing release report'});}
else{
  const tsx=resolve(repositoryRoot,'node_modules/tsx/dist/cli.mjs');
  const tested=spawnSync(process.execPath,[tsx,'--test',...suites],{cwd:repositoryRoot,encoding:'utf8',timeout:900_000,maxBuffer:32*1024*1024,windowsHide:true});
  const transcript=`${tested.stdout??''}\n${tested.stderr??''}`;const tests=Number((transcript.match(/[#ℹ]\s*tests\s+(\d+)/)||[])[1]??0),failures=Number((transcript.match(/[#ℹ]\s*fail\s+(\d+)/)||[])[1]??-1);
  const cli=readBounded(resolve(stellarRoot,'src/cli.cpp')),driver=readBounded(resolve(stellarRoot,'tools/build-package.ps1')),plan=readBounded(resolve(stellarRoot,'TRANCHE_PLAN.md'));
  gates=[
    {name:'T0-T6-and-legacy-conformance',passed:tested.status===0&&tests>0&&failures===0,evidence:`${tests} tests; ${failures} failures`},
    {name:'native-run-refusal',passed:/if\(args\[0\]=="run"\).*S7001/s.test(cli)&&!/\bLoadLibrary\b/.test(cli),evidence:'run is a coded refusal and no native loader is present'},
    {name:'inspection-only-link',passed:/\/noentry/i.test(driver)&&/\/nodefaultlib/i.test(driver)&&!/Start-Process|Invoke-Expression|\biex\b/i.test(driver),evidence:'fixed non-entering link; no dynamic script execution'},
    {name:'capability-authorization-isolation-gate',passed:/checksum integrity is not authorization/i.test(plan)&&/OS-enforced native process isolation/i.test(plan),evidence:'mandatory gate remains documented and closed'},
    {name:'repository-native-artifact-cleanliness',passed:binaryArtifacts(stellarRoot).length===0,evidence:'no COFF, PE, PDB, or DLL artifacts persisted under v0.1'},
  ];
}
gates.sort((left,right)=>left.name.localeCompare(right.name));const passed=gates.every((gate)=>gate.passed===true);
const report={schema:'stellar.release-acceptance/v0.1',status:passed?'pass':'fail',target:'windows-x86_64-msvc',profile:'stellar-lab-v0',nativeCodeExecuted: false,executionEnabled:false,homeostasis:'NOT_EVALUATED',gates};
mkdirSync(dirname(resolve(reportPath)),{recursive:true});writeFileSync(resolve(reportPath),`${JSON.stringify(report)}\n`,{encoding:'utf8',flag:'wx'});process.stdout.write(`${JSON.stringify({status:report.status,report:resolve(reportPath),nativeCodeExecuted:false})}\n`);process.exit(passed?0:1);
