import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root=resolve('native/stellar/v0_1/service');
const runtime=readFileSync(resolve(root,'src/service_runtime.cpp'),'utf8');
const header=readFileSync(resolve(root,'src/service_runtime.h'),'utf8');
const custodian=readFileSync(resolve(root,'src/custodian_service.cpp'),'utf8');
const broker=readFileSync(resolve(root,'src/execution_broker_service.cpp'),'utf8');
const contract=readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_T7D_D2_OVERLAPPED_SERVICE.md'),'utf8');
const policy=JSON.parse(readFileSync(resolve(root,'t7d-d2-service-runtime.canonical.json'),'utf8'));
const evidence=JSON.parse(readFileSync(resolve('native/stellar/v0_1/evidence/t7d-d2-offline-acceptance.json'),'utf8'));

test('D2 transport is overlapped, deadline-bounded, stop-aware and drains cancellation',()=>{
  assert.match(runtime,/FILE_FLAG_OVERLAPPED/);
  assert.match(runtime,/WaitForMultipleObjects/);
  assert.match(runtime,/CancelIoEx/);
  assert.match(runtime,/GetOverlappedResult/);
  assert.match(runtime,/ConnectNamedPipe\([^;]+&overlapped/);
  assert.match(runtime,/ReadFile\([^;]+&overlapped/);
  assert.match(runtime,/WriteFile\([^;]+&overlapped/);
  assert.doesNotMatch(runtime,/ConnectNamedPipe\(pipe,nullptr\)/);
});

test('D2 uses exactly one bounded message frame and refuses truncation or trailing bytes',()=>{
  assert.match(header,/kMaximumFrameBytes\s*=\s*32768/);
  assert.match(runtime,/ERROR_MORE_DATA/);
  assert.match(runtime,/frameBytes\s*!=\s*sizeof\(DWORD\)\s*\+\s*declaredBytes/);
  assert.match(runtime,/oneRequestPerConnection/);
  assert.match(header,/DWORD deadlineMs/);
});

test('D2 pipe topology is local-only, first-instance and exact',()=>{
  assert.match(runtime,/PIPE_REJECT_REMOTE_CLIENTS/);
  assert.match(runtime,/FILE_FLAG_FIRST_PIPE_INSTANCE/);
  assert.match(header,/kMaximumConcurrentConnections\s*=\s*1/);
  assert.match(custodian,/AegisStellarCustodian\.v0\.1/);
  assert.match(broker,/AegisStellarExecutionBroker\.v0\.1/);
  for(const source of [custodian,broker]){
    assert.match(source,/AegisStellarLabGateway/);
    assert.doesNotMatch(source,/AegisGateway/);
  }
});

test('D2 authenticates exact held OS and SCM identity before signed request verification',()=>{
  for(const token of ['GetNamedPipeClientProcessId','ImpersonateNamedPipeClient','OpenThreadToken','TokenUser','EqualSid','OpenProcess','GetProcessTimes','QueryFullProcessImageNameW','CreateFileW','FileIdInfo','WinVerifyTrust','Sha256Handle','OpenSCManagerW','OpenServiceW','QueryServiceStatusEx','QueryServiceConfigW','SERVICE_RUNNING','SERVICE_CONFIG_SERVICE_SID_INFO','SERVICE_SID_TYPE_UNRESTRICTED','SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO','SERVICE_CONFIG_FAILURE_ACTIONS','SERVICE_CONFIG_FAILURE_ACTIONS_FLAG'])assert.match(runtime,new RegExp(token));
  assert.match(header,/HANDLE processHandle/);
  assert.match(header,/HANDLE imageHandle/);
  assert.match(header,/FILETIME creationTime/);
  assert.match(header,/FILE_ID_128 imageFileId/);
  assert.match(header,/std::wstring imageSha256/);
  assert.match(header,/std::wstring signerThumbprint/);
  assert.match(header,/imageVolumeSerial/);
  assert.match(runtime,/CreateFileW\(peer\.imagePath\.c_str\(\), GENERIC_READ,\s*FILE_SHARE_READ,/s);
  assert.doesNotMatch(runtime,/CreateFileW\(peer\.imagePath[\s\S]{0,120}FILE_SHARE_WRITE|CreateFileW\(peer\.imagePath[\s\S]{0,120}FILE_SHARE_DELETE/);
  assert.match(runtime,/WTD_CACHE_ONLY_URL_RETRIEVAL/);
});

test('D2 emits exact nonce challenge and verifies strict canonical ES256 reply bindings',()=>{
  assert.match(runtime,/stellar-pipe-[\s\S]{0,100}challenge-v0\.1/);
  for(const token of ['protocolVersion','serverServiceSid','serverServiceName','serverPid','serverCreationTime','serverImageHash','serverImageFileId','serverImageVolumeSerial','serverImageSigner','serverInstanceId','nonce','issuedAt','expiresAt','BCryptGenRandom','BCryptVerifySignature','challengeHash','expectedAction'])assert.match(runtime,new RegExp(token));
  assert.match(runtime,/5000/);
  assert.match(runtime,/strictCanonical/);
  assert.match(header,/VerifyAndConsumeStrictCanonicalEs256/);
  const handshake=runtime.slice(runtime.indexOf('bool PerformAuthenticatedHandshake'));
  const write=handshake.indexOf('WriteBoundedFrame');
  const read=handshake.indexOf('ReadBoundedFrame');
  const identity=handshake.indexOf('AuthenticatePipeClient');
  const verify=handshake.indexOf('VerifyAndConsumeStrictCanonicalEs256');
  assert.ok(write>=0&&write<read&&read<identity&&identity<verify);
  assert.doesNotMatch(handshake,/strictCanonical\.find/);
  for(const state of ['connected','challenge_sent','reply_received','identity_bound','accepted','refused','stopped'])assert.match(header,new RegExp(state));
});

test('D2 holds START_PENDING through ordered readiness and accepts preshutdown cancellation',()=>{
  assert.match(runtime,/SERVICE_ACCEPT_PRESHUTDOWN/);
  assert.match(runtime,/SERVICE_CONTROL_PRESHUTDOWN/);
  assert.match(runtime,/SERVICE_START_PENDING/);
  assert.match(runtime,/dwCheckPoint/);
  const ordered=/config[\s\S]+release-manifest[\s\S]+key-registry[\s\S]+protected-acl-roots[\s\S]+pipe-dacl-create[\s\S]+self-attestation-static-imports[\s\S]+worker-ready/;
  assert.match(custodian,ordered);
  assert.match(broker,ordered);
  assert.match(runtime,/SERVICE_RUNNING/);
  assert.match(header,/StartupReadiness/);
});

test('D2 service source preserves OWN_PROCESS, required privilege and closed execution semantics',()=>{
  assert.match(runtime,/SERVICE_WIN32_OWN_PROCESS/);
  for(const source of [custodian,broker]){
    assert.match(source,/SeChangeNotifyPrivilege/);
    assert.match(source,/SeImpersonatePrivilege/);
    assert.match(source,/S7001/i);
  }
  assert.doesNotMatch(broker,/CreateProcessW|ShellExecuteW|WinExec|LoadLibraryW/);
  assert.match(runtime,/GetSecurityInfo/);
  assert.match(runtime,/OWNER_SECURITY_INFORMATION\s*\|\s*DACL_SECURITY_INFORMATION/);
  assert.match(runtime,/0x0012008b/);
  assert.match(runtime,/FILE_CREATE_PIPE_INSTANCE/);
  assert.match(header,/kGatewayPipeClientDesiredAccess\s*=\s*\n?\s*GENERIC_READ\s*\|\s*FILE_WRITE_DATA/);
  assert.match(runtime,/ERROR_SERVICE_NOT_ACTIVE/);
});

test('D2 canonical policy and doctrine preserve the offline fail-closed boundary',()=>{
  assert.equal(policy.schema,'stellar.t7d-d2-service-runtime/v0.1');
  assert.equal(policy.applicationClient,'NT SERVICE\\AegisStellarLabGateway');
  assert.equal(policy.systemApplicationAuthority,false);
  assert.equal(policy.execution.s7001,'CLOSED');
  assert.equal(policy.status,'OFFLINE_FAIL_CLOSED');
  assert.deepEqual(policy.readiness,['config','release-manifest','key-registry','protected-acl-roots','pipe-dacl-create','self-attestation-static-imports','worker-ready']);
  assert.match(contract,/REJECTED FOR INSTALL/);
  assert.match(contract,/cannot report RUNNING/);
  assert.match(contract,/No elevation, SCM mutation, key creation/);
  assert.equal(evidence.build.status,'passed');
  assert.equal(evidence.limitations.installAuthorized,false);
  assert.equal(evidence.limitations.authenticatedInstalledRegistry,'absent-fail-closed');
});
