import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

test("broker loopback compatibility is a package-bound dynamic WFP lease", () => {
  const source = readFileSync(resolve("native/stellar/v0_1/sandbox/src/wfp_loopback_deny.h"), "utf8");
  const broker = readFileSync(resolve("native/stellar/v0_1/sandbox/src/sandbox_broker.cpp"), "utf8");
  assert.match(source, /FWPM_SESSION_FLAG_DYNAMIC/);
  assert.match(source, /FWPM_LAYER_ALE_AUTH_CONNECT_V4/);
  assert.match(source, /FWPM_CONDITION_ALE_PACKAGE_ID/);
  assert.match(source, /FWPM_CONDITION_IP_REMOTE_ADDRESS/);
  assert.match(source, /FWP_ACTION_BLOCK/);
  assert.match(source, /FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT/);
  assert.match(source, /FwpmFilterDeleteByKey0/);
  assert.match(broker, /LoopbackDenyLease/);
  assert.match(broker, /loopbackDeny\.Install\(cleanupState\.sid\)/);
});
