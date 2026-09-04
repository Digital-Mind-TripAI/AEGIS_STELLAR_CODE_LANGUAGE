import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve("native/stellar/v0_1");

test("service source and lifecycle policy retain separate identities, provisioned CNG custody, strict ACLs, and no automatic install", () => {
  const common = readFileSync(resolve(root, "service/src/service_common.cpp"), "utf8");
  const custodian = readFileSync(
    resolve(root, "service/src/custodian_service.cpp"),
    "utf8",
  );
  const broker = readFileSync(
    resolve(root, "service/src/execution_broker_service.cpp"),
    "utf8",
  );
  const install = readFileSync(
    resolve(root, "service/tools/install-services.ps1"),
    "utf8",
  );
  const installerModel = readFileSync(
    resolve(root, "service/d4-installer-model.ts"),
    "utf8",
  );
  const preflight = readFileSync(
    resolve(root, "service/tools/preflight-services.ps1"),
    "utf8",
  );
  const policy = JSON.parse(
    readFileSync(resolve(root, "service/t7c-service-boundary.canonical.json"), "utf8"),
  );

  assert.match(custodian, /MS_PLATFORM_CRYPTO_PROVIDER/);
  assert.doesNotMatch(
    custodian,
    /MS_KEY_STORAGE_PROVIDER|NCryptCreatePersistedKey|NCryptSetProperty/,
  );
  assert.match(custodian, /NCRYPT_EXPORT_POLICY_PROPERTY/);
  assert.match(custodian, /NCRYPT_ALGORITHM_PROPERTY/);
  assert.match(custodian, /AegisStellarCustodian/);
  assert.match(broker, /AegisStellarExecutionBroker/);
  assert.match(common, /SetDefaultDllDirectories/);
  assert.match(common, /LOAD_LIBRARY_SEARCH_SYSTEM32/);
  assert.match(common, /WinVerifyTrust/);
  assert.match(common, /FileIdInfo/);
  assert.match(common, /FILE_ATTRIBUTE_REPARSE_POINT/);
  assert.match(common, /LookupAccountNameW/);
  assert.match(common, /ConvertStringSecurityDescriptorToSecurityDescriptorW/);
  for (const dll of ["advapi32.dll", "ws2_32.dll", "user32.dll"])
    assert.match(common, new RegExp(dll, "i"));
  assert.match(installerModel, /ZERO_MUTATION_PROPOSED_STATE/);
  assert.match(installerModel, /unknownResources/);
  assert.match(install, /T7D_D4_APPLY_CLOSED_REVIEW_ONLY_USE_SEPARATE_DISCOVERY_TOOL/);
  assert.doesNotMatch(install, /New-Service|Set-Acl|New-NetFirewallRule/);
  assert.doesNotMatch(install, /SupportsShouldProcess|WhatIf|npx/);
  assert.match(preflight, /Administrator/);
  assert.doesNotMatch(preflight, /New-Service|sc\.exe\s+create/i);
  assert.equal(policy.s7001, "CLOSED");
  assert.equal(policy.arbitraryExecution, false);
  assert.deepEqual(policy.actions, ["stellar.t7b.fixed-security-probe-suite/v0.1"]);
});
