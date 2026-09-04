import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { fixedResources, PLAN_ARTIFACT_HASH, PLAN_HASH, validateOperatorReceipt, validateT7eEvidence } from "../service/t7e-semantic-validator.ts";
import { validateDraft202012 } from "../service/draft202012-validator.ts";
import { DISCOVERY_SCHEMA_HASH, RECEIPT_SCHEMA_HASH, validateOutputFiles } from "../service/tools/validate-t7e-output.ts";
const source = readFileSync(
  resolve("native/stellar/v0_1/service/src/target_host_discovery.cpp"),
  "utf8",
);
const build = readFileSync(
  resolve("native/stellar/v0_1/service/tools/build-target-host-discovery.ps1"),
  "utf8",
);
const aclSource=readFileSync(resolve("native/stellar/v0_1/service/src/protected_output_acl.cpp"),"utf8");
const hostileSource=readFileSync(resolve("native/stellar/v0_1/service/src/target_host_discovery_hostile_selftest.cpp"),"utf8");
const acceptedD4PlanFixture=resolve("native/stellar/v0_1/tests/fixtures/t7e/accepted-d4-install-plan.canonical.json");
const nativeImportsFixture=resolve("native/stellar/v0_1/tests/fixtures/t7e/target-host-discovery.native-imports.txt");
const fixtureSha256=(path:string)=>`sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
const NATIVE_IMPORTS_FIXTURE_SHA256="sha256:7b9c1c86855262a5cec69345d910e6b8f55ad9b23a15e4f28339f106c8aa51fd";
test("T7E static fixtures retain their pinned input hashes",()=>{
  assert.equal(fixtureSha256(acceptedD4PlanFixture),PLAN_ARTIFACT_HASH);
  assert.equal(fixtureSha256(nativeImportsFixture),NATIVE_IMPORTS_FIXTURE_SHA256);
});
test("fixed discovery has read-only scope and no elevation, network, scripting, or mutation APIs", () => {
  for (const required of [
    "TokenElevation",
    "TokenUser",
    "TokenPrivileges",
    "OpenSCManagerW",
    "QueryServiceConfigW",
    "QueryServiceStatusEx",
    "SERVICE_CONFIG_SERVICE_SID_INFO",
    "SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO",
    "SERVICE_CONFIG_FAILURE_ACTIONS",
    "QueryServiceObjectSecurity",
    "GetSecurityInfo",
    "FileIdInfo",
    "FindFirstStreamW",
    "nNumberOfLinks",
    "NCryptOpenStorageProvider",
    "NCryptOpenKey",
    "NCRYPT_EXPORT_POLICY_PROPERTY",
    "RegOpenKeyExW",
    "GetComputerNameW",
    "beforeSelfReadDigest",
    "afterSelfReadDigest",
    "CREATE_NEW",
  ])
    assert.match(source, new RegExp(required));
  for (const forbidden of [
    "ShellExecute",
    "CreateProcess",
    "WinExec",
    "URLDownload",
    "WinHttp",
    "InternetOpen",
    "StartService",
    "CreateService",
    "ChangeServiceConfig",
    "RegSetValue",
    "NCryptCreatePersistedKey",
    "CertAdd",
    "SetNamedSecurityInfo",
    "CoCreateInstance",
    "NetFwPolicy2",
  ])
    assert.doesNotMatch(source, new RegExp(forbidden));
  assert.match(source, /argc==2&&wcscmp\(argv\[1\],L"--self-test"\)/);
  assert.match(source, /argc!=3\|\|wcscmp\(argv\[1\],L"--output"\)/);
});
test("native build is warning-clean deterministic and contains no script-host link", () => {
  for (const flag of ["/W4", "/WX", "/Brepro", "/guard:cf", "/CETCOMPAT"])
    assert.ok(build.includes(flag));
  assert.doesNotMatch(build, /npx|tsx|powershell\.exe|node\.exe/i);
  assert.match(build, /target_host_discovery_hostile_selftest\.cpp/);
  assert.match(build, /T7E_HOSTILE_NATIVE_ACCEPTANCE_FAILED/);
  assert.match(build,/protected_output_acl\.cpp/);
});
test("production output ACL policy is shared, generic-mapped, allowlisted, and hostile-tested",()=>{for(const token of ["MapGenericMask","FILE_WRITE_EA","FILE_DELETE_CHILD","WRITE_DAC","WRITE_OWNER","ACCESS_ALLOWED_OBJECT_ACE_TYPE","ACCESS_DENIED_OBJECT_ACE_TYPE","ProtectedOutputHandleAllowed"])assert.match(aclSource,new RegExp(token));for(const sid of ["SECURITY_LOCAL_SYSTEM_RID","DOMAIN_ALIAS_RID_ADMINS"])assert.match(aclSource,new RegExp(sid));assert.match(source,/ProtectedOutputHandleAllowed/);for(const token of ["AU","BU","GW","GA","DC","FILE_WRITE_EA","WRITE_DAC","WRITE_OWNER","OA;;GW","ProtectedOutputHandleAllowed"])assert.match(hostileSource,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")));});
test("provider injection covers deterministic success and injected observation failure", () => {
  assert.match(source, /class FakeProvider/);
  assert.match(source, /Mode::drift/);
  assert.match(source, /self-read digest changed/);
  assert.match(source, /scope\.size\(\)!=91/);
  assert.match(source, /!=77/);
  assert.match(source, /ValidOutputLeaf/);
});
test("native import inspection contains observation primitives and no mutator or network libraries", () => {
  const imports = readFileSync(
    resolve(
      nativeImportsFixture,
    ),
    "utf8",
  );
  for (const required of [
    "OpenProcessToken",
    "QueryServiceConfigW",
    "GetFileInformationByHandleEx",
    "NCryptOpenKey",
    "CertOpenStore",
    "RegGetValueW",
  ])
    assert.match(imports, new RegExp(required));
  for (const forbidden of [
    "CreateServiceW",
    "StartServiceW",
    "ChangeServiceConfigW",
    "RegSetValue",
    "NCryptCreatePersistedKey",
    "CertAddCertificate",
    "WinHttp",
    "WS2_32.dll",
  ])
    assert.doesNotMatch(imports, new RegExp(forbidden, "i"));
});
test("accepted D4 plan artifact and internal plan are pinned before compilation", () => {
  assert.match(
    build,
    /437e6d3dd6343d226825dffe98f00e1e0649987f20ee1b980af21e281dd8b3a8/,
  );
  assert.match(
    build,
    /9958eb87768bbf305d0b4a1f859f86ed8cfb5bb94234bc7c82bb98fc65a0a3b0/,
  );
  assert.match(build, /proposed\.Count -ne 91/);
  assert.match(build, /Count -ne 77/);
});
test("v0.2 schema fixes exact correspondence and known-unavailable resource states", () => {
  const schema = JSON.parse(
    readFileSync(
      resolve(
        "native/stellar/v0_1/schemas/stellar-target-host-discovery-v0.2.schema.json",
      ),
      "utf8",
    ),
  );
  const snapshots = schema.properties.snapshots.properties;
  assert.equal(snapshots.resourceCount.const, 91);
  assert.equal(snapshots.resources.minProperties, 91);
  assert.equal(snapshots.resources.maxProperties, 91);
  assert.equal(snapshots.resources.required.length,91);
  assert.equal(Object.keys(snapshots.resources.properties).length,91);
  assert.equal(snapshots.resources.additionalProperties,false);
  assert.equal(
    schema.properties.schema.const,
    "stellar.t7e-target-host-discovery/v0.2",
  );
  const receipt=JSON.parse(readFileSync(resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-receipt-v0.1.schema.json"),"utf8"));
  assert.equal(receipt.additionalProperties,false);assert.equal(receipt.properties.exitCode.const,0);assert.equal(receipt.properties.flushSucceeded.const,true);assert.equal(receipt.properties.rootPolicyVerified.const,true);
  const hostile=JSON.parse(readFileSync(resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-hostile-selftest-v0.1.schema.json"),"utf8"));
  assert.equal(hostile.additionalProperties,false);assert.equal(hostile.properties.hostileFixturesAccepted.const,true);assert.equal(hostile.properties.result.const,0);
  assert.equal(DISCOVERY_SCHEMA_HASH,"sha256:6844bd75f71472cf00523facf392f551a5daf068d2d1fdec39db678fa2ef55c5");assert.equal(RECEIPT_SCHEMA_HASH,"sha256:782ea8a63b67f05e1309abd2e22848cb8357e2a5008f0c97d9ce014fde8ed405");
});
test("external semantic validator rejects correspondence, stability, authority, and receipt drift",()=>{
  const plan=acceptedD4PlanFixture;
  const resources=fixedResources(plan); const unavailable={error:2,status:"unavailable"};
  const observed=Object.fromEntries(resources.map(r=>[r.resourceId,{kind:r.kind,status:"unavailable",observation:r.kind==="key"?{acceptedCount:0,acceptedProvider:"",configuredProvider:"Microsoft Platform Crypto Provider",machineFlag:32,platform:{observation:unavailable,provider:"Microsoft Platform Crypto Provider",status:"unavailable"},software:{observation:unavailable,provider:"Microsoft Software Key Storage Provider",status:"unavailable"},softwarePresentNotAccepted:false}:unavailable}]));
  const digest="sha256:"+"a".repeat(64);const evidence:any={afterSelfReadDigest:digest,beforeSelfReadDigest:digest,noTargetMutationObserved:true,outputWrite:{mode:"CREATE_NEW_AFTER_STABLE_READ",recordedSeparately:true},proposedPlanHash:PLAN_HASH,schema:"stellar.t7e-target-host-discovery/v0.2",snapshots:{host:{architecture:"x64",computerName:"fixture",installRoot:"C:\\Program Files\\AEGIS\\Stellar\\v0.1",os:"windows",planArtifactHash:PLAN_ARTIFACT_HASH,planHash:PLAN_HASH},resourceCount:91,resources:observed,token:unavailable},stableDoubleRead:true};
  validateT7eEvidence(evidence,resources);
  for(const mutate of [(x:any)=>delete x.snapshots.resources[resources[0].resourceId],(x:any)=>x.snapshots.resources[resources[0].resourceId].kind="wrong",(x:any)=>x.afterSelfReadDigest="sha256:"+"b".repeat(64),(x:any)=>x.proposedPlanHash=digest]){const copy=structuredClone(evidence);mutate(copy);assert.throws(()=>validateT7eEvidence(copy,resources));}
  const bytes=Buffer.from("{}");const receipt={bytes:2,exitCode:0,fileId:"a".repeat(32),flushSucceeded:true,path:"C:\\ProgramData\\AEGIS\\Stellar\\v0.1\\evidence\\target-host-discovery.canonical.json",rootPolicyVerified:true,schema:"stellar.t7e-operator-receipt/v0.1",sha256:"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",volumeSerial:"1"};validateOperatorReceipt(receipt,bytes);for(const key of ["exitCode","flushSucceeded","rootPolicyVerified","sha256"]){const copy:any={...receipt};copy[key]=key==="exitCode"?1:key==="sha256"?digest:false;assert.throws(()=>validateOperatorReceipt(copy,bytes));}
  const discoverySchema=JSON.parse(readFileSync(resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-v0.2.schema.json"),"utf8"));const receiptSchema=JSON.parse(readFileSync(resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-receipt-v0.1.schema.json"),"utf8"));validateDraft202012(discoverySchema,evidence);validateDraft202012(receiptSchema,receipt);
  for(const mutate of [(x:any)=>x.snapshots.token={elevated:"false",privileges:[],sid:"S-1-5-1"},(x:any)=>{const id=resources.find(r=>r.kind==="file")!.resourceId;x.snapshots.resources[id]={kind:"file",status:"known",observation:{attributes:0}}},(x:any)=>x.extra=true]){const copy=structuredClone(evidence);mutate(copy);assert.throws(()=>validateDraft202012(discoverySchema,copy));}
  for(const mutate of [(x:any)=>x.bytes=-1,(x:any)=>x.bytes=67108865,(x:any)=>x.fileId="XYZ",(x:any)=>x.volumeSerial="1x",(x:any)=>x.flushSucceeded="true",(x:any)=>x.extra=true]){const copy:any=structuredClone(receipt);mutate(copy);assert.throws(()=>validateDraft202012(receiptSchema,copy));}
  const evidenceBytes=Buffer.from(JSON.stringify(evidence));const boundReceipt={...receipt,bytes:evidenceBytes.length,sha256:`sha256:${createHash("sha256").update(evidenceBytes).digest("hex")}`};const discoverySchemaPath=resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-v0.2.schema.json"),receiptSchemaPath=resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-receipt-v0.1.schema.json");validateOutputFiles(plan,evidenceBytes,Buffer.from(JSON.stringify(boundReceipt)),discoverySchemaPath,receiptSchemaPath);assert.throws(()=>validateOutputFiles(plan,evidenceBytes,Buffer.from(JSON.stringify(boundReceipt)),resolve("native/stellar/v0_1/schemas/stellar-target-host-discovery-hostile-selftest-v0.1.schema.json"),receiptSchemaPath),/schema authority hash mismatch/);
});
