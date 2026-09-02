import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
} from "node:crypto";
import {
  closeSync,
  fstatSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { keyIdForPublicKey } from "../../../../server/stellar-capability-contract.ts";
import {
  D4_RESOURCE_KINDS,
  executeTransaction,
  MockTransactionDriver,
  observedSnapshot,
  planOfflineInstall,
  releaseDestination,
  type ReleaseInstallFile,
  type ResourceSnapshot,
} from "../service/d4-installer-model.ts";
import {
  buildUnsignedManifest,
  canonicalReleaseJson,
  RELEASE_KINDS,
  signManifest,
  verifySignedRelease,
  type D4ReleaseManifest,
  type D4SignedRelease,
  type PackageInspection,
  type VerifiedD4Release,
} from "../service/d4-release-package.ts";

const releaseHash = `sha256:${"a".repeat(64)}`;
const authorityHashes = [`sha256:${"b".repeat(64)}`];
const executionRoot = mkdtempSync(join(tmpdir(), "stellar-d4-execute-"));
const executionPath = join(executionRoot, "stellar-native-runner.exe");
writeFileSync(executionPath, Buffer.alloc(100, 7));
const executionHandle = openSync(executionPath, "r");
const executionStat = fstatSync(executionHandle);
const executionSha = `sha256:${createHash("sha256").update(readFileSync(executionPath)).digest("hex")}`;
const releaseFiles: ReleaseInstallFile[] = [
  {
    path: "bin/stellar-native-runner.exe",
    sha256: executionSha,
    bytes: 100,
    kind: "runner",
    sourceIdentity: {
      device: String(executionStat.dev),
      fileId: String(executionStat.ino),
      bytes: executionStat.size,
      sha256: executionSha,
      retainedHandle: true,
    },
  },
];
const verifiedExecutionRelease = {
  manifest: {
    files: [
      {
        path: releaseFiles[0].path,
        kind: releaseFiles[0].kind,
        sha256: executionSha,
        bytes: 100,
      },
    ],
  },
  root: executionRoot,
  handles: new Map([[releaseFiles[0].path, executionHandle]]),
  releaseHash,
  close() {},
} as unknown as VerifiedD4Release;
test.after(() => {
  closeSync(executionHandle);
  rmSync(executionRoot, { recursive: true, force: true });
});
const execute = (
  p: ReturnType<typeof plan>,
  driver = new MockTransactionDriver(),
  hashes = authorityHashes,
) => executeTransaction(p, verifiedExecutionRelease, hashes, driver);
const plan = (observed?: ReadonlyMap<string, ResourceSnapshot>) =>
  planOfflineInstall({ releaseHash, authorityHashes, releaseFiles, observed });
const rehashPlan = <T extends { planHash: string }>(value: T): T => {
  const { planHash: _ignored, ...body } = value;
  return {
    ...value,
    planHash: `sha256:${createHash("sha256").update(canonicalReleaseJson(body)).digest("hex")}`,
  };
};
function knownSnapshots(matchesDesired = false) {
  const base = plan();
  const desired = new Map(
    base.proposed.map((x) => [x.resourceId, x.desiredState]),
  );
  return new Map(
    base.snapshots.map((s) => [
      s.id,
      observedSnapshot(
        s.id,
        s.kind,
        "known",
        matchesDesired ? { ...desired.get(s.id)! } : { prior: true },
      ),
    ]),
  );
}

test("zero-mutation planner covers every state class and marks privileged readback unknown", () => {
  const p = plan();
  assert.equal(p.mode, "ZERO_MUTATION_PROPOSED_STATE");
  assert.equal(p.mutationsPerformed, 0);
  assert.equal(p.servicesRemainStoppedUntilReadback, true);
  for (const kind of D4_RESOURCE_KINDS)
    assert.ok(p.snapshots.some((x) => x.kind === kind));
  assert.ok(p.snapshots.every((x) => x.observation === "unknown_not_queried"));
  assert.ok(
    p.snapshots.some(
      (x) => x.id === "release-file:bin/stellar-native-runner.exe",
    ),
  );
  assert.match(p.planHash, /^sha256:[a-f0-9]{64}$/);
});

test("plan fixes every artifact destination and exact stopped service configuration", () => {
  const root = "C:\\Program Files\\AEGIS\\Stellar\\v0.1";
  const mappings: Array<[string, string, string]> = [
    [
      "bin/AegisStellarCustodian.exe",
      "service",
      `${root}\\bin\\AegisStellarCustodian.exe`,
    ],
    [
      "bin/AegisStellarExecutionBroker.exe",
      "broker",
      `${root}\\bin\\AegisStellarExecutionBroker.exe`,
    ],
    [
      "bin/stellar-t7b-fixed-probe.exe",
      "runner",
      `${root}\\bin\\stellar-t7b-fixed-probe.exe`,
    ],
    [
      "bin/stellar-t7b-sandbox.exe",
      "runner",
      `${root}\\bin\\stellar-t7b-sandbox.exe`,
    ],
    [
      "bin/stellar-native-compiler.exe",
      "compiler",
      `${root}\\bin\\stellar-native-compiler.exe`,
    ],
    [
      "bin/stellar-native-runner.exe",
      "runner",
      `${root}\\bin\\stellar-native-runner.exe`,
    ],
    ["stdlib/core.stellar", "stdlib", `${root}\\stdlib\\core.stellar`],
    ["schemas/a.json", "schema", `${root}\\schemas\\a.json`],
    ["config/a.json", "config", `${root}\\config\\a.json`],
    ["policy/a.json", "canonical-policy", `${root}\\config\\a.json`],
    ["adapter/a.ps1", "adapter", `${root}\\tools\\a.ps1`],
    ["scripts/a.ps1", "script", `${root}\\tools\\a.ps1`],
    ["docs/a.md", "documentation", `${root}\\docs\\a.md`],
  ];
  for (const [path, kind, destination] of mappings)
    assert.equal(releaseDestination(path, kind, root), destination);
  const services = plan().proposed.filter((x) => x.kind === "service");
  assert.equal(services.length, 2);
  for (const service of services) {
    const state = service.desiredState as Record<string, unknown>;
    assert.equal(state.state, "stopped");
    assert.equal(state.serviceType, "SERVICE_WIN32_OWN_PROCESS");
    assert.equal(state.startMode, "SERVICE_DEMAND_START");
    assert.equal(state.sidType, "SERVICE_SID_TYPE_UNRESTRICTED");
    assert.match(String(state.binaryPath), /^"[A-Z]:\\.*\.exe"$/);
    assert.match(String(state.account), /^NT SERVICE\\AegisStellar/);
    assert.ok(state.serviceSddl);
    assert.deepEqual(state.requiredPrivileges, [
      "SeChangeNotifyPrivilege",
      "SeImpersonatePrivilege",
    ]);
  }
});

test("apply refuses unknown privileged state and exact readback is required", () => {
  assert.throws(() => execute(plan()), /exact prestate/);
  const p = plan(knownSnapshots());
  const failing = p.proposed[3];
  const driver = new MockTransactionDriver({
    [`readback:${failing.resourceId}`]: { wrong: true },
  });
  const rehashPlan = <T extends { planHash: string }>(value: T): T => {
    const { planHash: _ignored, ...body } = value;
    return {
      ...value,
      planHash: `sha256:${createHash("sha256").update(canonicalReleaseJson(body)).digest("hex")}`,
    };
  };
  const result = execute(p, driver);
  assert.equal(result.status, "rolled_back");
  assert.equal(result.servicesStarted, false);
  assert.ok(
    result.records.some((x) => x.phase === "readback" && x.result === "failed"),
  );
});

test("every install stage has fault injection and reverse rollback; rollback failure is explicit", () => {
  const p = plan(knownSnapshots());
  for (const mutation of p.proposed) {
    const d = new MockTransactionDriver({
      [`apply:${mutation.resourceId}`]: 17,
    });
    const result = execute(p, d);
    assert.equal(result.status, "rolled_back");
    assert.equal(result.servicesStarted, false);
    assert.ok(d.calls.includes(`readback:${mutation.resourceId}`));
    assert.ok(d.calls.includes(`restore:${mutation.resourceId}`));
  }
  const failAt = p.proposed.at(-1)!;
  const prior = p.proposed.at(-2)!;
  const result = execute(
    p,
    new MockTransactionDriver({
      [`apply:${failAt.resourceId}`]: 9,
      [`restore:${prior.resourceId}`]: 8,
    }),
  );
  assert.equal(result.status, "rollback_incomplete");
  assert.deepEqual(result.rollbackFailures, [prior.resourceId]);
});

test("native exit codes are exact, success stays stopped, and already-desired install is idempotent", () => {
  const p = plan(knownSnapshots());
  const driver = new MockTransactionDriver();
  const ok = execute(p, driver);
  assert.equal(ok.status, "installed_stopped_verified");
  assert.equal(ok.servicesStarted, false);
  assert.deepEqual(driver.heldHandles, [executionHandle]);
  const again = plan(knownSnapshots(true));
  assert.equal(again.proposed.length, 0);
  assert.equal(execute(again).status, "no_change");
});

test("transaction refuses tampered hash/order/duplicates/release and unauthorized driver", () => {
  const p = plan(knownSnapshots());
  assert.throws(
    () => execute(p, new MockTransactionDriver(), [`sha256:${"9".repeat(64)}`]),
    /authority/,
  );
  const wrongIdentity = structuredClone(p);
  const fileMutation = wrongIdentity.proposed.find((x) => x.kind === "file")!;
  fileMutation.desiredState = {
    ...fileMutation.desiredState,
    sourceIdentity: {
      ...(fileMutation.desiredState.sourceIdentity as Record<string, unknown>),
      fileId: "wrong-file-id",
    },
  };
  fileMutation.desiredStateHash = `sha256:${createHash("sha256").update(canonicalReleaseJson(fileMutation.desiredState)).digest("hex")}`;
  fileMutation.readback = `canonical:${fileMutation.desiredStateHash}`;
  assert.throws(
    () => execute(rehashPlan(wrongIdentity), new MockTransactionDriver()),
    /identity mismatch/,
  );
  assert.throws(
    () =>
      execute(
        { ...p, planHash: `sha256:${"0".repeat(64)}` },
        new MockTransactionDriver(),
      ),
    /plan hash/,
  );
  assert.throws(
    () =>
      executeTransaction(
        p,
        {
          ...verifiedExecutionRelease,
          releaseHash: `sha256:${"d".repeat(64)}`,
        },
        authorityHashes,
        new MockTransactionDriver(),
      ),
    /release mismatch/,
  );
  assert.throws(
    () => execute(p, new MockTransactionDriver({ authorize: false })),
    /authorization/,
  );
  const malformed = structuredClone(p);
  malformed.proposed[0].sequence = 2;
  assert.throws(
    () => execute(rehashPlan(malformed), new MockTransactionDriver()),
    /order/,
  );
  const duplicate = structuredClone(p);
  duplicate.proposed[1].resourceId = duplicate.proposed[0].resourceId;
  assert.throws(
    () => execute(rehashPlan(duplicate), new MockTransactionDriver()),
    /duplicate/,
  );
});

test("failed stage is restored unless atomic no-mutation is explicitly proved", () => {
  const p = plan(knownSnapshots()),
    first = p.proposed[0];
  const normal = new MockTransactionDriver({
    [`apply:${first.resourceId}`]: 23,
  });
  execute(p, normal);
  assert.deepEqual(normal.calls.slice(0, 3), [
    `apply:${first.resourceId}`,
    `readback:${first.resourceId}`,
    `restore:${first.resourceId}`,
  ]);
  const atomic = new MockTransactionDriver({
    [`apply:${first.resourceId}`]: 23,
    [`atomic:${first.resourceId}`]: true,
  });
  const result = execute(p, atomic);
  assert.deepEqual(atomic.calls, [`apply:${first.resourceId}`]);
  assert.ok(result.records.some((x) => x.result === "atomic_no_mutation"));
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "stellar-d4-"));
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
    kid = keyIdForPublicKey(pair.publicKey);
  const pe = new Set(["service", "broker", "runner", "compiler"]);
  const files = RELEASE_KINDS.map((kind, index) => ({
    path: `payload/${String(index).padStart(2, "0")}-${kind}.bin`,
    kind,
    bytes: Buffer.from(`${kind}:reviewed`),
    imports: pe.has(kind) ? ["KERNEL32.dll!WriteFile"] : [],
    signers: pe.has(kind) ? ["LAB-THUMBPRINT"] : [],
    authenticodePolicy: pe.has(kind)
      ? ("REQUIRE_VALID_EMBEDDED" as const)
      : null,
    nativeInspectionHash: pe.has(kind) ? `sha256:${"e".repeat(64)}` : null,
  }));
  for (const f of files) {
    const path = join(root, ...f.path.split("/"));
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, f.bytes);
  }
  const manifest = buildUnsignedManifest({
    releaseId: "stellar-v0.1-d4",
    signingPolicy: "LAB_SELF_SIGNED",
    signerKid: kid,
    files,
  });
  const envelope = signManifest(manifest, pair.privateKey);
  const inspect: PackageInspection = {
    pe: async () => ({
      imports: ["KERNEL32.dll!WriteFile"],
      signers: ["LAB-THUMBPRINT"],
      authenticodePolicy: "REQUIRE_VALID_EMBEDDED",
      inspectionHash: `sha256:${"e".repeat(64)}`,
      nativeInspected: true,
    }),
    streams: async () => ["::$DATA"],
    acl: async () => "reviewed",
  };
  return { root, pair, kid, files, manifest, envelope, inspect };
}

test("full manifest covers compiler/runtime/policies/config/scripts/docs with exact hashes, imports and signers", async (t) => {
  const f = fixture();
  t.after(() => rmSync(f.root, { recursive: true, force: true }));
  for (const kind of RELEASE_KINDS)
    assert.ok(f.manifest.files.some((x) => x.kind === kind));
  const verified = await verifySignedRelease(
    f.root,
    f.envelope,
    (k) => (k === f.kid ? f.pair.publicKey : undefined),
    f.inspect,
  );
  assert.match(verified.releaseHash, /^sha256:/);
  verified.close();
});

test("release refuses bad signer, hash, path, ACL, imports, hardlinks and reparse roots", async (t) => {
  const f = fixture();
  t.after(() => rmSync(f.root, { recursive: true, force: true }));
  const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  await assert.rejects(
    () =>
      verifySignedRelease(f.root, f.envelope, () => other.publicKey, f.inspect),
    /bad signer/,
  );
  const target = join(f.root, ...f.files[0].path.split("/"));
  writeFileSync(target, "tampered");
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        f.inspect,
      ),
    /bad hash/,
  );
  writeFileSync(target, f.files[0].bytes);
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        { ...f.inspect, acl: async () => "unknown_requires_elevation" },
      ),
    /ACL/,
  );
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        { ...f.inspect, streams: async () => ["::$DATA", ":evil:$DATA"] },
      ),
    /ADS/,
  );
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        {
          ...f.inspect,
          pe: async () => ({
            imports: ["EVIL.dll!Run"],
            signers: ["LAB-THUMBPRINT"],
            authenticodePolicy: "REQUIRE_VALID_EMBEDDED",
            inspectionHash: `sha256:${"e".repeat(64)}`,
            nativeInspected: true,
          }),
        },
      ),
    /imports\/signer/,
  );
  const changed = {
    ...f.inspect,
    acl: async (path: string) => {
      writeFileSync(path, "changed-during-inspection");
      return "reviewed" as const;
    },
  };
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        changed,
      ),
    /post-inspection/,
  );
  writeFileSync(target, f.files[0].bytes);
  const alias = join(f.root, "hardlink.bin");
  linkSync(target, alias);
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        f.envelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        f.inspect,
      ),
    /hardlink/,
  );
  rmSync(alias);
  assert.throws(
    () =>
      buildUnsignedManifest({
        releaseId: "x",
        signingPolicy: "EXTERNAL_SIGNER",
        signerKid: f.kid,
        files: [...f.files, { ...f.files[0], path: "../escape" }],
      }),
    /invalid release file/,
  );
  const collision = structuredClone(f.manifest);
  collision.files[1].path = collision.files[0].path.toUpperCase();
  collision.files.sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  const collisionEnvelope = signManifest(collision, f.pair.privateKey);
  await assert.rejects(
    () =>
      verifySignedRelease(
        f.root,
        collisionEnvelope,
        (k) => (k === f.kid ? f.pair.publicKey : undefined),
        f.inspect,
      ),
    /structure/,
  );
  assert.throws(
    () =>
      buildUnsignedManifest({
        releaseId: "x",
        signingPolicy: "EXTERNAL_SIGNER",
        signerKid: f.kid,
        files: [...f.files, { ...f.files[0], path: "payload/file.exe:evil" }],
      }),
    /invalid release file/,
  );
  assert.throws(
    () =>
      buildUnsignedManifest({
        releaseId: "x",
        signingPolicy: "EXTERNAL_SIGNER",
        signerKid: f.kid,
        files: f.files.map((x) =>
          x.kind === "runner" ? { ...x, signers: [] } : x,
        ),
      }),
    /PE imports\/signers\/inspection missing/,
  );
  const linkRoot = `${f.root}-link`;
  try {
    symlinkSync(f.root, linkRoot, "junction");
    await assert.rejects(
      () =>
        verifySignedRelease(
          linkRoot,
          f.envelope,
          (k) => (k === f.kid ? f.pair.publicKey : undefined),
          f.inspect,
        ),
      /reparse/,
    );
  } finally {
    rmSync(linkRoot, { force: true });
  }
});

test("LAB_SELF_SIGNED and EXTERNAL_SIGNER are declarations only; library never mints or trusts a certificate", () => {
  const f = fixture();
  try {
    for (const policy of ["LAB_SELF_SIGNED", "EXTERNAL_SIGNER"] as const) {
      const m = buildUnsignedManifest({
        releaseId: `r-${policy}`,
        signingPolicy: policy,
        signerKid: f.kid,
        files: f.files,
      });
      assert.equal(m.signingPolicy, policy);
    }
    assert.equal(
      "certificate" in (f.manifest as unknown as Record<string, unknown>),
      false,
    );
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

const acceptedD4ReviewEnvelopeRoot = resolve(
  "native/stellar/v0_1/release/stellar-v0.1-d4-v02-review-envelope-2026-09-02-d4-refresh-05",
);

test("accepted review envelope contains a complete reviewed unsigned payload with exact byte hashes", () => {
  const root = acceptedD4ReviewEnvelopeRoot;
  const manifestBytes = readFileSync(
    resolve(root, "release-manifest.v0.2.canonical.json"),
  );
  const envelopeBytes = readFileSync(
    resolve(root, "release-envelope.v0.2.canonical.json"),
  );
  const publicKeyBytes = readFileSync(
    resolve(root, "LAB-REVIEW-SIGNER-PUBLIC.pem"),
  );
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as {
    installable: boolean;
    files: Array<{ path: string; kind: string; bytes: number; sha256: string }>;
  };
  const envelope = JSON.parse(envelopeBytes.toString("utf8")) as D4SignedRelease;
  const envelopeManifest = JSON.parse(envelope.manifest) as D4ReleaseManifest;
  assert.equal(manifest.installable, false);
  assert.equal(manifest.files.length, 95);
  for (const kind of RELEASE_KINDS)
    assert.ok(manifest.files.some((x) => x.kind === kind));
  for (const file of manifest.files) {
    const bytes = readFileSync(resolve(root, ...file.path.split("/")));
    assert.equal(bytes.length, file.bytes);
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      file.sha256,
    );
  }
  const receipt = JSON.parse(
    readFileSync(resolve(root, "REVIEW-ENVELOPE-RECEIPT.canonical.json"), "utf8"),
  ) as {
    certificateMinted: boolean;
    installable: boolean;
    privateKeyRetained: boolean;
    envelopeHash: string;
    publicKeyHash: string;
    releaseHash: string;
    signerKid: string;
    trustModified: boolean;
  };
  assert.equal(receipt.certificateMinted, false);
  assert.equal(receipt.installable, false);
  assert.equal(receipt.privateKeyRetained, false);
  assert.equal(receipt.trustModified, false);
  assert.equal(
    receipt.envelopeHash,
    `sha256:${createHash("sha256").update(envelopeBytes).digest("hex")}`,
  );
  assert.equal(
    receipt.publicKeyHash,
    `sha256:${createHash("sha256").update(publicKeyBytes).digest("hex")}`,
  );
  assert.equal(receipt.signerKid, envelopeManifest.signer.kid);
  assert.equal(
    receipt.releaseHash,
    `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`,
  );
});

test("D4 review envelope builder hashes PE inspections with Windows PowerShell-compatible APIs", () => {
  const builder = readFileSync(
    resolve("native/stellar/v0_1/service/tools/build-d4-v02-review-envelope.ps1"),
    "utf8",
  );
  assert.match(builder, /function Get-Sha256Hex\(\[byte\[\]\]\$bytes\)/);
  assert.match(
    builder,
    /nativeInspectionHash='sha256:'\+\(Get-Sha256Hex \(\[Text\.Encoding\]::UTF8\.GetBytes\(\$json\)\)\)/,
  );
  assert.doesNotMatch(builder, /SHA256\]::HashData|Convert\]::ToHexString/);
  assert.match(builder, /\$utf8NoBom=\[Text\.UTF8Encoding\]::new\(\$false\)/);
  assert.match(builder, /\[IO\.File\]::WriteAllText\(\$ip,\$inspectionJson,\$utf8NoBom\)/);
  assert.match(builder, /\[IO\.File\]::WriteAllText\(\$cp,\$closureJson,\$utf8NoBom\)/);
  assert.match(builder, /\[IO\.File\]::WriteAllText\(\$inventory,\$inventoryJson,\$utf8NoBom\)/);
  assert.doesNotMatch(builder, /Set-Content.*utf8NoBOM/);
});

test("D4 review envelope builder refuses unaccepted T7b broker or runner bytes before output emission", () => {
  const builder = readFileSync(
    resolve("native/stellar/v0_1/service/tools/build-d4-v02-review-envelope.ps1"),
    "utf8",
  );
  assert.match(builder, /function Get-VerifiedT7bSourceHash\(\[string\]\$path\)/);
  assert.match(builder, /t7b-target-host-acceptance\.json/);
  assert.match(builder, /\$bindings\.brokerSha256/);
  assert.match(builder, /\$bindings\.runnerSha256/);
  assert.match(builder, /D4_T7B_BROKER_HASH_MISMATCH/);
  assert.match(builder, /D4_T7B_RUNNER_HASH_MISMATCH/);
  assert.match(builder, /D4_T7B_ACCEPTANCE_BINDINGS_INVALID/);
  assert.ok(
    builder.indexOf("D4_T7B_BROKER_HASH_MISMATCH") <
      builder.indexOf("New-Item -ItemType Directory $out"),
  );
});

test("D4 review envelope builder rehashes copied T7b runtime bytes before further assembly", () => {
  const builder = readFileSync(
    resolve("native/stellar/v0_1/service/tools/build-d4-v02-review-envelope.ps1"),
    "utf8",
  );
  assert.match(
    builder,
    /function Assert-CopiedT7bRuntimeBinding\(\[string\]\$relative,\[string\]\$expected,\[string\]\$failure\)/,
  );
  assert.match(
    builder,
    /Assert-CopiedT7bRuntimeBinding 'bin\/stellar-t7b-sandbox\.exe' \(\[string\]\$bindings\.brokerSha256\) 'D4_T7B_COPIED_BROKER_HASH_MISMATCH'/,
  );
  assert.match(
    builder,
    /Assert-CopiedT7bRuntimeBinding 'bin\/stellar-t7b-fixed-probe\.exe' \(\[string\]\$bindings\.runnerSha256\) 'D4_T7B_COPIED_RUNNER_HASH_MISMATCH'/,
  );
  assert.ok(
    builder.indexOf("D4_T7B_COPIED_BROKER_HASH_MISMATCH") >
      builder.indexOf(
        "Add-File (Join-Path $SandboxBuildRoot 'stellar-t7b-fixed-probe.exe')",
      ),
  );
  assert.ok(
    builder.indexOf("D4_T7B_COPIED_RUNNER_HASH_MISMATCH") <
      builder.indexOf('Add-File "$repo\\native\\stellar\\.out\\phase-a-final\\host'),
  );
});

test("D4 finalizer rechecks accepted T7b bytes immediately before review-envelope signing", () => {
  const finalizer = readFileSync(
    resolve("native/stellar/v0_1/service/tools/finalize-d4-v02-release.ts"),
    "utf8",
  );
  const builder = readFileSync(
    resolve("native/stellar/v0_1/service/tools/build-d4-v02-review-envelope.ps1"),
    "utf8",
  );
  assert.match(
    finalizer,
    /usage: finalize <root> <inventory> <expected-broker-sha256> <expected-runner-sha256>/,
  );
  assert.match(finalizer, /const finalGateError\s*=.*D4_T7B_FINAL_/);
  assert.match(finalizer, /const requiredRuntimeEntries\s*=\s*\[/);
  assert.match(finalizer, /entries\.length\s*===\s*0\)\s*throw finalGateError\(required\.kind,\s*'ENTRY_MISSING'\)/);
  assert.match(finalizer, /entries\.length\s*>\s*1\)\s*throw finalGateError\(required\.kind,\s*'ENTRY_DUPLICATE'\)/);
  assert.match(finalizer, /entries\[0\]\.kind\s*!==\s*required\.kind\)\s*throw finalGateError\(required\.kind,\s*'ENTRY_WRONG_KIND'\)/);
  assert.match(finalizer, /if \(`sha256:\$\{createHash\('sha256'\)\.update\(bytes\)\.digest\('hex'\)\}` !== accepted\) throw finalGateError\(required\.kind, 'HASH_MISMATCH'\)/);
  assert.ok(
    finalizer.indexOf("D4_T7B_FINAL_") < finalizer.indexOf("signManifest(manifest"),
  );
  assert.match(
    builder,
    /finalize-d4-v02-release\.ts" \$out \$inventory \(\[string\]\$bindings\.brokerSha256\) \(\[string\]\$bindings\.runnerSha256\)/,
  );
});

test("D4 finalizer requires one root-confined accepted runtime binding record before key generation", () => {
  const finalizer = readFileSync(
    resolve("native/stellar/v0_1/service/tools/finalize-d4-v02-release.ts"),
    "utf8",
  );
  assert.match(finalizer, /const acceptancePath = 'runtime\/t7b-target-host-acceptance\.json'/);
  assert.match(finalizer, /acceptanceEntries\.length === 0\) throw inventoryError\('ACCEPTANCE_ENTRY_MISSING'\)/);
  assert.match(finalizer, /acceptanceEntries\.length > 1\) throw inventoryError\('ACCEPTANCE_ENTRY_DUPLICATE'\)/);
  assert.match(finalizer, /function confinedPath\(value: string, label: string\)/);
  assert.match(finalizer, /lstatSync\(path\)\.isSymbolicLink\(\)/);
  assert.match(finalizer, /throw inventoryError\(`\$\{label\}_REPARSE_PATH`\)/);
  assert.match(finalizer, /function readAcceptedRuntimeBinding\(bytes: Buffer\)/);
  assert.match(finalizer, /record\.schema !== 'stellar\.t7b-target-host-acceptance\/v0\.1'/);
  assert.match(finalizer, /record\.status !== 'passed'/);
  assert.match(finalizer, /record\.executionClass !== 'FIXED_SECURITY_PROBE_ONLY'/);
  assert.match(finalizer, /ACCEPTANCE_BINDING_MISMATCH/);
  assert.ok(
    finalizer.indexOf("const acceptedBindings = readAcceptedRuntimeBinding") <
      finalizer.indexOf("const pair = generateKeyPairSync"),
  );
});

test("v0.2 review envelope binds exact T7b runtime closure and is truthfully noninstallable", () => {
  const root = acceptedD4ReviewEnvelopeRoot,
    manifestText = readFileSync(
      resolve(root, "release-manifest.v0.2.canonical.json"),
      "utf8",
    ),
    envelopeText = readFileSync(
      resolve(root, "release-envelope.v0.2.canonical.json"),
      "utf8",
    ),
    manifest = JSON.parse(manifestText) as D4ReleaseManifest,
    envelope = JSON.parse(envelopeText) as D4SignedRelease,
    key = createPublicKey(
      readFileSync(resolve(root, "LAB-REVIEW-SIGNER-PUBLIC.pem")),
    );
  assert.equal(canonicalReleaseJson(manifest), manifestText);
  assert.equal(canonicalReleaseJson(envelope), envelopeText);
  assert.equal(envelope.manifest, manifestText);
  assert.ok(
    verify(
      "sha256",
      Buffer.from(manifestText),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(envelope.signature, "base64url"),
    ),
  );
  assert.equal(manifest.installable, false);
  assert.equal(
    new Set(manifest.files.map((x) => x.path.toLowerCase())).size,
    manifest.files.length,
  );
  for (const file of manifest.files) {
    const bytes = readFileSync(resolve(root, ...file.path.split("/")));
    assert.equal(bytes.length, file.bytes);
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      file.sha256,
    );
  }
  const sandbox = manifest.files.find(
      (x) => x.path === "bin/stellar-t7b-sandbox.exe",
    )!,
    runner = manifest.files.find(
      (x) => x.path === "bin/stellar-t7b-fixed-probe.exe",
    )!;
  assert.equal(
    sandbox.sha256,
    "sha256:086563b4b132fbdae17218679a31ba555dd504e825a2e89a858b86d10feec0ad",
  );
  assert.equal(
    runner.sha256,
    "sha256:1d1197fe1b7aa86e0fd12db1e4bac8a0b532c1c22ff5f0a491acdffa6eb9f123",
  );
  for (const pe of manifest.files.filter((x) =>
    ["service", "broker", "runner", "compiler"].includes(x.kind),
  )) {
    assert.ok(pe.imports.length);
    assert.deepEqual(pe.signers, ["AUTHENTICODE:UNSIGNED"]);
    assert.equal(pe.authenticodePolicy, "UNSIGNED_REVIEW_ONLY");
    assert.ok(
      manifest.files.some(
        (x) =>
          x.path ===
          `inspection/${pe.path.split("/").at(-1)}.native-inspection.json`,
      ),
    );
  }
  const closure = JSON.parse(
    readFileSync(
      resolve(root, "runtime/runtime-dependency-closure.canonical.json"),
      "utf8",
    ),
  ) as {
    closed: boolean;
    installedPaths: string[];
    runtimeBindings: Record<string, string>;
  };
  assert.equal(closure.closed, true);
  for (const expected of [
    "stellar-t7b-sandbox.exe",
    "stellar-t7b-fixed-probe.exe",
    "AegisStellarCustodian.exe",
    "AegisStellarExecutionBroker.exe",
  ])
    assert.ok(closure.installedPaths.some((x) => x.endsWith(expected)));
  assert.equal(closure.runtimeBindings.brokerSha256, sandbox.sha256.slice(7));
  assert.equal(closure.runtimeBindings.runnerSha256, runner.sha256.slice(7));
});
