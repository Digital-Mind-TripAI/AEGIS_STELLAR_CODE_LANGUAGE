import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { DurableReceiptLedger, SignedKeyRegistry } from '../service/d3-offline-model.ts';

const root=resolve('native/stellar/v0_1');
const source=(name:string)=>readFileSync(resolve(root,'service/src',name),'utf8');

test('native canonical JSON rejects duplicates, noncanonical order, floats, escapes and trailing data',()=>{
  const parser=source('canonical_json.cpp');
  for(const token of ['duplicate_key','noncanonical_key_order','unsupported_number','noncanonical_escape','trailing_data','maximumDepth','maximumBytes']) assert.match(parser,new RegExp(token));
  assert.match(source('canonical_json.h'),/ParseCanonicalChallenge|ParseCanonicalSignedRequest|ParseCanonicalCapabilityContract/);
});

test('native canonical JSON establishes the Windows base declarations before CNG',()=>{
  const parser=source('canonical_json.cpp');
  assert.ok(parser.indexOf('#include <windows.h>') < parser.indexOf('#include <bcrypt.h>'));
});

test('provisioning is a separate one-shot Platform KSP tool with no overwrite and explicit software policy',()=>{
  const provision=source('provision_keys.cpp');
  assert.match(provision,/MS_PLATFORM_CRYPTO_PROVIDER/);
  assert.match(provision,/NCryptCreatePersistedKey/);
  assert.match(provision,/NCRYPT_ECC_CURVE_NAME_PROPERTY|NCRYPT_ECDSA_P256_ALGORITHM/);
  assert.match(provision,/NCRYPT_EXPORT_POLICY_PROPERTY/);
  assert.match(source('key_custody.cpp'),/NCryptExportKey[^;]+BCRYPT_ECCPUBLIC_BLOB/s);
  assert.match(provision,/SetEntriesInAclW/);
  assert.match(provision,/SetSecurityDescriptorOwner/);
  assert.doesNotMatch(provision,/NCRYPT_OVERWRITE_KEY_FLAG/);
  assert.match(provision,/--allow-software-custody/);
  assert.match(provision,/refus(e|ing).*exist/i);
});

test('runtime signing opens provisioned keys, proves SPKI kid and refuses private export',()=>{
  const custody=source('key_custody.cpp');
  assert.match(custody,/NCryptOpenKey/);
  assert.match(custody,/NCryptSignHash/);
  assert.match(custody,/BCRYPT_ECCPUBLIC_BLOB/);
  assert.match(custody,/SubjectPublicKeyInfo|SPKI/);
  assert.match(custody,/BCryptHashData/);
  assert.match(custody,/NCRYPT_EXPORT_POLICY_PROPERTY/);
  assert.match(custody,/NCryptExportKey[^;]+NCRYPT_PKCS8_PRIVATE_KEY_BLOB/s);
});

test('gateway helper uses exact rights, authenticates held server identity and verifies signed reply',()=>{
  const gateway=source('gateway_pipe_client.cpp');
  assert.match(gateway,/GENERIC_READ\s*\|\s*FILE_WRITE_DATA/);
  assert.doesNotMatch(gateway,/GENERIC_WRITE/);
  for(const item of ['GetNamedPipeServerProcessId','AuthenticatePinnedProcess','ParseCanonicalChallenge','ChallengeMatches','signRequest','verifyReply','GENERIC_READ','FILE_WRITE_DATA']) assert.match(gateway,new RegExp(item));
  assert.match(source('service_runtime.cpp'),/peer\.processHandle[\s\S]+peer\.imageHandle/);
});

test('durable registry enforces one active key, rotation overlap and immediate revocation',()=>{
  const registry=new SignedKeyRegistry();
  registry.install({kid:'k1',notBefore:1,notAfter:100,revokedAt:null},'sig1');
  assert.equal(registry.resolve('k1',10)?.kid,'k1');
  registry.rotate({kid:'k2',notBefore:20,notAfter:200,revokedAt:null},'sig2',20,10);
  assert.equal(registry.active(21).kid,'k2');
  assert.equal(registry.resolve('k1',25)?.kid,'k1');
  assert.equal(registry.resolve('k1',31),undefined);
  registry.revoke('k2',22,'sig3');
  assert.equal(registry.resolve('k2',22),undefined);
});

test('lost response retry returns the prior signed receipt and never reruns',()=>{
  const ledger=new DurableReceiptLedger(); let runs=0;
  const first=ledger.execute('request-1','hash-a',()=>({payload:'done',signature:'sig',runs:++runs}));
  const retry=ledger.execute('request-1','hash-a',()=>({payload:'wrong',signature:'wrong',runs:++runs}));
  assert.deepEqual(retry,first); assert.equal(runs,1);
  assert.throws(()=>ledger.execute('request-1','hash-b',()=>first),/binding conflict/);
  const recovered=DurableReceiptLedger.recover(ledger.snapshot());
  assert.deepEqual(recovered.execute('request-1','hash-a',()=>{throw new Error('rerun');}),first);
});

test('durable journal v0.2 separates Broker evidence and makes every mutation a locked reload-CAS-replace-reopen transaction',()=>{
  const header=source('durable_state.h'),native=source('durable_state.cpp'),parser=source('canonical_json.cpp');
  for(const field of ['brokerCanonicalReceipt','brokerSignature','journalRecordSignature','brokerReceiptHash']) assert.match(header,new RegExp(field));
  for(const operation of ['Lock lock','LoadBestLocked','PersistAndRevalidate','FlushFileBuffers','MoveFileExW','MOVEFILE_REPLACE_EXISTING','MOVEFILE_WRITE_THROUGH']) assert.match(native,new RegExp(operation));
  assert.match(parser,/stellar\.replay-journal-record\/v0\.2/);
  assert.doesNotMatch(parser,/stellar\.replay-journal-record\/v0\.1/);
});

test('consume verifies the active Broker key and every authority binding before terminal publication',()=>{
  const native=source('durable_state.cpp');
  assert.match(native,/VerifyRegistryBrokerReceipt/);
  assert.match(native,/BrokerReceiptMatches/);
  for(const field of ['requestHash','contractId','contractHash','nonce','operationId','releaseHash','action','hostId','targetService','brokerService','brokerImageHash','runnerHash']) assert.match(native,new RegExp(`receipt\\.${field}|r\\.${field}`));
  assert.match(native,/status\s*!=\s*"completed"|status=="completed"/);
});

test('native selftest uses a real multiprocess race and crash-corruption-restart cases',()=>{
  const selftest=source('durable_state_selftest.cpp');
  for(const token of ['CreateProcessW','winners\\s*!=\\s*1','truncated','corrupt','\\.new','PRIOR_RECEIPT','BrokerSig']) assert.match(selftest,new RegExp(token));
});

test('readiness gates are predicates and both services require exact SCM configuration',()=>{
  const runtime=source('service_runtime.cpp');
  assert.match(runtime,/Checkpoint\(const wchar_t \*gateName, bool gatePassed\)/);
  assert.match(runtime,/if \(!gatePassed\)/);
  const scm=source('scm_readiness.cpp');
  for(const service of ['AegisStellarCustodian','AegisStellarExecutionBroker']) assert.match(scm,new RegExp(service));
  for(const item of ['SERVICE_WIN32_OWN_PROCESS','SERVICE_SID_TYPE_UNRESTRICTED','SeChangeNotifyPrivilege','SeImpersonatePrivilege','QueryServiceConfig2W']) assert.match(scm,new RegExp(item));
});

test('D3 remains offline, install closed, and S7001 closed',()=>{
  const doctrine=readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_T7D_D3_OFFLINE_COMPLETION.md'),'utf8');
  assert.match(doctrine,/REJECTED FOR INSTALL/);
  assert.match(doctrine,/S7001 CLOSED/);
  assert.match(doctrine,/live-only gates/i);
});
