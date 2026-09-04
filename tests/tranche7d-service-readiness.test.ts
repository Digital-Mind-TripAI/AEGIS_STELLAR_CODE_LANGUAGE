import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
const root = resolve("native/stellar/v0_1/service");
const runtime = readFileSync(resolve(root, "src/service_runtime.cpp"), "utf8");
const custodian = readFileSync(
  resolve(root, "src/custodian_service.cpp"),
  "utf8",
);
const broker = readFileSync(
  resolve(root, "src/execution_broker_service.cpp"),
  "utf8",
);
const install = readFileSync(
  resolve(root, "tools/install-services.ps1"),
  "utf8",
);
const installerModel = readFileSync(
  resolve(root, "d4-installer-model.ts"),
  "utf8",
);
const planEmitter = readFileSync(
  resolve(root, "tools/emit-d4-install-plan.ts"),
  "utf8",
);
const discovery = readFileSync(
  resolve(root, "tools/discover-d4-install-plan.ps1"),
  "utf8",
);

test("both services implement real SCM lifecycle and bounded stop control", () => {
  for (const source of [custodian, broker]) {
    assert.match(source, /RunWindowsService/);
    assert.match(source, /ServiceStopRequested/);
  }
  assert.match(runtime, /StartServiceCtrlDispatcherW/);
  assert.match(runtime, /RegisterServiceCtrlHandlerExW/);
  assert.match(runtime, /SERVICE_CONTROL_STOP/);
  assert.match(runtime, /SERVICE_CONTROL_SHUTDOWN/);
  assert.match(runtime, /SERVICE_STOP_PENDING/);
});
test("pipes reject remote and unauthenticated clients and bind SID PID image and bounded frames", () => {
  assert.match(runtime, /PIPE_REJECT_REMOTE_CLIENTS/);
  assert.match(runtime, /GetNamedPipeClientProcessId/);
  assert.match(runtime, /ImpersonateNamedPipeClient/);
  assert.match(runtime, /OpenThreadToken/);
  assert.match(runtime, /TokenUser/);
  assert.match(runtime, /EqualSid/);
  assert.match(runtime, /QueryFullProcessImageNameW/);
  assert.match(runtime, /declaredBytes\s*>\s*maxBytes/);
  assert.match(runtime, /32768/);
  assert.match(runtime, /FILE_FLAG_FIRST_PIPE_INSTANCE/);
  for (const source of [custodian, broker]) {
    assert.match(source, /AegisStellarLabGateway/);
    assert.match(source, /T7C_SCHEMA_OR_COMMAND_REFUSED|fixed-probes-only/);
  }
});
test("Custodian opens only a pre-provisioned TPM issuer key and preserves rotation seams", () => {
  assert.match(
    custodian,
    /Worker\(HANDLE stop,[^)]*\).*OpenProvisionedIssuerKey/s,
  );
  assert.match(custodian, /MS_PLATFORM_CRYPTO_PROVIDER/);
  assert.match(custodian, /NCRYPT_EXPORT_POLICY_PROPERTY/);
  assert.match(custodian, /NCRYPT_ALGORITHM_PROPERTY/);
  assert.match(custodian, /NCRYPT_ECDSA_P256_ALGORITHM/);
  assert.match(custodian, /NCryptOpenKey/);
  assert.doesNotMatch(
    custodian,
    /NCryptCreatePersistedKey|NCryptFinalizeKey|NCryptSetProperty|MS_KEY_STORAGE_PROVIDER|SOFTWARE_BOUND|NTE_BAD_KEYSET|NCRYPT_OVERWRITE_KEY_FLAG/,
  );
  assert.match(custodian, /revocationRegistry/);
  assert.match(custodian, /rotation/);
  assert.match(
    custodian,
    /--offline-self-test.*return stellar::service::RunWindowsService/s,
  );
});
test("Broker remains health/status only and fixed execution is not reachable through the pipe", () => {
  assert.match(broker, /fixed-probes-only/);
  assert.match(broker, /executionEnabled\\\":false/);
  assert.match(broker, /durable-[\s\S]{0,100}replay-handoff-required/);
  assert.doesNotMatch(
    broker,
    /CreateProcessW|ShellExecute|WinExec|LoadLibrary/,
  );
});
test("D4 installer emits only zero-mutation proposed state and keeps live apply closed", () => {
  assert.match(installerModel, /ZERO_MUTATION_PROPOSED_STATE/);
  assert.match(installerModel, /unknownResources/);
  assert.match(installerModel, /servicesRemainStoppedUntilReadback/);
  assert.match(installerModel, /successExitCodes:\s*\[0\]/);
  assert.match(installerModel, /failure-readback/);
  assert.match(planEmitter, /verifySignedRelease/);
  assert.match(planEmitter, /authority must remain outside PackageRoot/);
  assert.match(planEmitter, /planOfflineInstall/);
  assert.match(install, /T7D_D4_APPLY_CLOSED_REVIEW_ONLY_USE_SEPARATE_DISCOVERY_TOOL/);
  assert.doesNotMatch(
    install,
    /New-Service|New-NetFirewallRule|Set-Acl|NCryptCreatePersistedKey/,
  );
  assert.doesNotMatch(discovery, /npx|Start-Process|RunAs|WhatIf/);
  assert.match(discovery, /node\.exe/);
});
test("install-readiness contract retains all independent A-L gates as blockers", () => {
  const contract = readFileSync(
    resolve("docs/STELLAR_WINDOWS_X64_V0_1_T7D_INSTALL_READINESS.md"),
    "utf8",
  );
  for (const gate of "ABCDEFGHIJKL")
    assert.match(contract, new RegExp(`\\*\\*${gate} —`));
  assert.match(contract, /REJECTED FOR INSTALL/);
  assert.match(contract, /S7001 CLOSED/);
});
