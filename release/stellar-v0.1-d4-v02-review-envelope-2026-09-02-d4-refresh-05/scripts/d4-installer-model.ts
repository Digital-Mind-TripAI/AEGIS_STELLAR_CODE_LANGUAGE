import { createHash } from "node:crypto";
import { fstatSync, readSync } from "node:fs";
import { canonicalContractJson } from "../../../../server/stellar-capability-contract.ts";
import {
  canonicalReleaseJson,
  type VerifiedD4Release,
} from "./d4-release-package.ts";

export const D4_RESOURCE_KINDS = [
  "service",
  "file",
  "directory",
  "acl",
  "key",
  "certificate",
  "firewall",
  "config",
  "registry",
  "resource-identity",
] as const;
export type D4ResourceKind = (typeof D4_RESOURCE_KINDS)[number];
export type Observation =
  "known" | "absent" | "unknown_requires_elevation" | "unknown_not_queried";
export type DesiredState = "present" | "absent" | "stopped" | "configured";
export interface ResourceSnapshot {
  id: string;
  kind: D4ResourceKind;
  observation: Observation;
  state: Readonly<Record<string, unknown>> | null;
  stateHash: string | null;
  restoration:
    | "restore_exact"
    | "remove_created"
    | "no_change"
    | "unknown_requires_elevation"
    | "unknown_not_queried";
}
export interface SourceFileIdentity {
  device: string;
  fileId: string;
  bytes: number;
  sha256: string;
  retainedHandle: true;
}
export interface ReleaseInstallFile {
  path: string;
  sha256: string;
  bytes: number;
  kind: string;
  sourceIdentity: SourceFileIdentity;
}
export interface ProposedMutation {
  sequence: number;
  resourceId: string;
  kind: D4ResourceKind;
  desired: DesiredState;
  desiredState: Readonly<Record<string, unknown>>;
  desiredStateHash: string;
  requiresElevation: boolean;
  nativeCommand: string | null;
  successExitCodes: number[];
  readback: string;
}
export interface InstallPlan {
  schema: "stellar.t7d-install-plan/v0.2";
  mode: "ZERO_MUTATION_PROPOSED_STATE";
  releaseHash: string;
  authorityHashes: string[];
  target: { os: "windows"; arch: "x64"; installRoot: string; dataRoot: string };
  snapshots: ResourceSnapshot[];
  proposed: ProposedMutation[];
  unknownResources: string[];
  servicesRemainStoppedUntilReadback: true;
  mutationsPerformed: 0;
  planHash: string;
}
const HASH = /^sha256:[a-f0-9]{64}$/;
const sha = (v: string | Buffer) =>
  `sha256:${createHash("sha256").update(v).digest("hex")}`;
const canonicalHash = (v: unknown) => sha(canonicalReleaseJson(v));
const cleanAbsolute = (v: string, f: string) => {
  if (
    !/^[A-Za-z]:\\/.test(v) ||
    v.includes("..") ||
    v.includes(":", 2) ||
    /[\0-\x1f]/.test(v)
  )
    throw new Error(`${f} must be a normalized local absolute Windows path`);
  return v.replace(/[\\/]+$/, "");
};
const privileged = new Set<D4ResourceKind>([
  "acl",
  "service",
  "key",
  "certificate",
  "firewall",
  "registry",
]);
function unknown(id: string, kind: D4ResourceKind): ResourceSnapshot {
  return {
    id,
    kind,
    observation: "unknown_not_queried",
    state: null,
    stateHash: null,
    restoration: "unknown_not_queried",
  };
}
export function observedSnapshot(
  id: string,
  kind: D4ResourceKind,
  observation: "known" | "absent",
  state: Record<string, unknown> | null,
): ResourceSnapshot {
  const value = state === null ? null : Object.freeze({ ...state });
  return {
    id,
    kind,
    observation,
    state: value,
    stateHash: value === null ? null : canonicalHash(value),
    restoration: observation === "absent" ? "remove_created" : "restore_exact",
  };
}
const SERVICE_SDDL =
  "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)";
export function releaseDestination(
  path: string,
  kind: string,
  installRoot: string,
): string {
  const leaf = path.split("/").at(-1)!;
  const exact: Record<string, string> = {
    "bin/AegisStellarCustodian.exe": `${installRoot}\\bin\\AegisStellarCustodian.exe`,
    "bin/AegisStellarExecutionBroker.exe": `${installRoot}\\bin\\AegisStellarExecutionBroker.exe`,
    "bin/stellar-t7b-sandbox.exe": `${installRoot}\\bin\\stellar-t7b-sandbox.exe`,
    "bin/stellar-t7b-fixed-probe.exe": `${installRoot}\\bin\\stellar-t7b-fixed-probe.exe`,
    "bin/stellar-native-compiler.exe": `${installRoot}\\bin\\stellar-native-compiler.exe`,
    "bin/stellar-native-runner.exe": `${installRoot}\\bin\\stellar-native-runner.exe`,
  };
  if (exact[path]) return exact[path];
  const folders: Record<string, string> = {
    stdlib: "stdlib",
    schema: "schemas",
    config: "config",
    "canonical-policy": "config",
    adapter: "tools",
    script: "tools",
    documentation: "docs",
    "static-imports": "inspection",
  };
  const folder = folders[kind];
  if (!folder) throw new Error(`unmapped release kind/path: ${kind}:${path}`);
  return `${installRoot}\\${folder}\\${leaf}`;
}
function serviceState(
  name: "AegisStellarCustodian" | "AegisStellarExecutionBroker",
  installRoot: string,
): Record<string, unknown> {
  const broker = name === "AegisStellarExecutionBroker";
  return {
    name,
    state: "stopped",
    binaryPath: `\"${installRoot}\\bin\\${name}.exe\"`,
    serviceType: "SERVICE_WIN32_OWN_PROCESS",
    account: `NT SERVICE\\${name}`,
    startMode: "SERVICE_DEMAND_START",
    delayedAutoStart: false,
    requiredPrivileges: ["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"],
    dependencies: broker ? ["AegisStellarCustodian"] : [],
    sidType: "SERVICE_SID_TYPE_UNRESTRICTED",
    failureActions: {
      resetSeconds: 86400,
      actions: ["restart/5000", "restart/15000", "none/0"],
      failureFlag: true,
    },
    serviceSddl: SERVICE_SDDL,
  };
}
function baseResources(
  files: readonly ReleaseInstallFile[],
  installRoot: string,
): [string, D4ResourceKind, Record<string, unknown>][] {
  const base: [string, D4ResourceKind, Record<string, unknown>][] = [
    ["dir:install", "directory", { path: "INSTALL_ROOT", exists: true }],
    ["dir:data", "directory", { path: "DATA_ROOT", exists: true }],
    ["acl:install", "acl", { template: "install-v0.2" }],
    ["acl:data", "acl", { template: "data-v0.2" }],
    [
      "service:custodian",
      "service",
      serviceState("AegisStellarCustodian", installRoot),
    ],
    [
      "service:broker",
      "service",
      serviceState("AegisStellarExecutionBroker", installRoot),
    ],
    [
      "registry:release",
      "registry",
      { key: "installed-release", releaseBound: true },
    ],
    ["key:issuer", "key", { existingRequired: true }],
    ["key:broker", "key", { existingRequired: true }],
    ["certificate:release", "certificate", { policy: "manifest-declared" }],
    ["firewall:custodian", "firewall", { outbound: "deny" }],
    ["firewall:broker", "firewall", { outbound: "deny" }],
    ["config:installed-release", "config", { releaseBound: true }],
    [
      "identity:install-volume",
      "resource-identity",
      { volumeAndFileIds: true },
    ],
  ];
  for (const file of files)
    base.push([
      `release-file:${file.path}`,
      "file",
      {
        destination: releaseDestination(file.path, file.kind, installRoot),
        sourcePath: file.path,
        sha256: file.sha256,
        bytes: file.bytes,
        releaseKind: file.kind,
        sourceIdentity: file.sourceIdentity,
      },
    ]);
  return base;
}
export function planOfflineInstall(input: {
  releaseHash: string;
  authorityHashes: string[];
  releaseFiles: ReleaseInstallFile[];
  installRoot?: string;
  dataRoot?: string;
  observed?: ReadonlyMap<string, ResourceSnapshot>;
}): InstallPlan {
  if (
    !HASH.test(input.releaseHash) ||
    !input.authorityHashes.length ||
    input.authorityHashes.some((x) => !HASH.test(x))
  )
    throw new Error("invalid release/authority hash");
  if (
    !input.releaseFiles.length ||
    new Set(input.releaseFiles.map((x) => x.path.toLowerCase())).size !==
      input.releaseFiles.length
  )
    throw new Error("release file inventory missing or colliding");
  for (const f of input.releaseFiles)
    if (
      !HASH.test(f.sha256) ||
      !Number.isSafeInteger(f.bytes) ||
      f.bytes < 1 ||
      !f.path ||
      f.sourceIdentity.sha256 !== f.sha256 ||
      f.sourceIdentity.bytes !== f.bytes ||
      f.sourceIdentity.retainedHandle !== true ||
      !f.sourceIdentity.device ||
      !f.sourceIdentity.fileId
    )
      throw new Error("invalid release file inventory");
  const installRoot = cleanAbsolute(
      input.installRoot ?? "C:\\Program Files\\AEGIS\\Stellar\\v0.1",
      "installRoot",
    ),
    dataRoot = cleanAbsolute(
      input.dataRoot ?? "C:\\ProgramData\\AEGIS\\Stellar\\v0.1",
      "dataRoot",
    );
  const resources = baseResources(input.releaseFiles, installRoot),
    ids = resources.map((x) => x[0]);
  if (new Set(ids).size !== ids.length)
    throw new Error("resource identity collision");
  const snapshots = resources.map(
    ([id, kind]) => input.observed?.get(id) ?? unknown(id, kind),
  );
  const proposed: ProposedMutation[] = [];
  for (const [id, kind, desiredState] of resources) {
    const snapshot = snapshots.find((x) => x.id === id)!;
    const desiredStateHash = canonicalHash(desiredState);
    if (snapshot.stateHash === desiredStateHash) {
      snapshot.restoration = "no_change";
      continue;
    }
    proposed.push({
      sequence: proposed.length + 1,
      resourceId: id,
      kind,
      desired:
        kind === "service"
          ? "stopped"
          : kind === "key" || kind === "certificate" || kind === "registry"
            ? "configured"
            : "present",
      desiredState: Object.freeze({ ...desiredState }),
      desiredStateHash,
      requiresElevation: privileged.has(kind),
      nativeCommand: privileged.has(kind) ? `native:${kind}:${id}` : null,
      successExitCodes: [0],
      readback: `canonical:${desiredStateHash}`,
    });
  }
  const noHash = {
    schema: "stellar.t7d-install-plan/v0.2" as const,
    mode: "ZERO_MUTATION_PROPOSED_STATE" as const,
    releaseHash: input.releaseHash,
    authorityHashes: [...input.authorityHashes].sort(),
    target: {
      os: "windows" as const,
      arch: "x64" as const,
      installRoot,
      dataRoot,
    },
    snapshots,
    proposed,
    unknownResources: snapshots
      .filter((x) => x.observation.startsWith("unknown"))
      .map((x) => x.id),
    servicesRemainStoppedUntilReadback: true as const,
    mutationsPerformed: 0 as const,
  };
  return { ...noHash, planHash: canonicalHash(noHash) };
}
export interface JournalRecord {
  sequence: number;
  phase: "snapshot" | "apply" | "failure-readback" | "readback" | "rollback";
  resourceId: string;
  result: "ok" | "failed" | "atomic_no_mutation";
  detail: string;
  previousHash: string;
  recordHash: string;
}
export interface TransactionResult {
  status:
    | "installed_stopped_verified"
    | "rolled_back"
    | "rollback_incomplete"
    | "no_change";
  records: JournalRecord[];
  rollbackFailures: string[];
  servicesStarted: false;
}
export interface ApplyResult {
  exitCode: number;
  atomicNoMutation: boolean;
}
export interface TransactionDriver {
  authorize(plan: InstallPlan, release: VerifiedD4Release): boolean;
  apply(m: ProposedMutation, heldSourceHandle: number | null): ApplyResult;
  readback(m: ProposedMutation): Readonly<Record<string, unknown>>;
  restore(snapshot: ResourceSnapshot): number;
}
function append(
  records: JournalRecord[],
  record: Omit<JournalRecord, "sequence" | "previousHash" | "recordHash">,
) {
  const base = {
    sequence: records.length + 1,
    ...record,
    previousHash: records.at(-1)?.recordHash ?? "GENESIS",
  };
  records.push({ ...base, recordHash: canonicalHash(base) });
}
function validatePlan(
  plan: InstallPlan,
  release: VerifiedD4Release,
  expectedAuthorityHashes: string[],
) {
  const expectedReleaseHash = release.releaseHash;
  if (
    plan.schema !== "stellar.t7d-install-plan/v0.2" ||
    plan.mode !== "ZERO_MUTATION_PROPOSED_STATE" ||
    plan.mutationsPerformed !== 0 ||
    plan.releaseHash !== expectedReleaseHash ||
    !HASH.test(expectedReleaseHash)
  )
    throw new Error("plan schema/release mismatch");
  const { planHash, ...body } = plan;
  if (canonicalHash(body) !== planHash) throw new Error("plan hash mismatch");
  if (
    !Array.isArray(plan.authorityHashes) ||
    !plan.authorityHashes.length ||
    plan.authorityHashes.length > 32 ||
    plan.authorityHashes.some((x) => !HASH.test(x)) ||
    new Set(plan.authorityHashes).size !== plan.authorityHashes.length ||
    plan.authorityHashes.some(
      (x, i) => i > 0 && plan.authorityHashes[i - 1] >= x,
    )
  )
    throw new Error("authority hashes invalid");
  if (
    plan.target.os !== "windows" ||
    plan.target.arch !== "x64" ||
    !/^([A-Za-z]):\\/.test(plan.target.installRoot) ||
    !/^([A-Za-z]):\\/.test(plan.target.dataRoot) ||
    plan.servicesRemainStoppedUntilReadback !== true
  )
    throw new Error("target/install invariant invalid");
  if (
    !Array.isArray(plan.snapshots) ||
    !plan.snapshots.length ||
    plan.snapshots.length > 256 ||
    !Array.isArray(plan.proposed) ||
    plan.proposed.length > 256 ||
    !Array.isArray(plan.unknownResources) ||
    plan.unknownResources.length ||
    new Set(plan.snapshots.map((x) => x.id)).size !== plan.snapshots.length ||
    new Set(plan.proposed.map((x) => x.resourceId)).size !==
      plan.proposed.length
  )
    throw new Error("duplicate resource or exact prestate absent");
  if (
    canonicalReleaseJson(plan.authorityHashes) !==
    canonicalReleaseJson([...expectedAuthorityHashes].sort())
  )
    throw new Error("authority hash mismatch");
  const releaseIds = plan.snapshots
    .filter((x) => x.id.startsWith("release-file:"))
    .map((x) => x.id.slice(13).toLowerCase());
  const manifestIds = release.manifest.files.map((x) => x.path.toLowerCase());
  if (
    !releaseIds.length ||
    canonicalReleaseJson([...releaseIds].sort()) !==
      canonicalReleaseJson([...manifestIds].sort()) ||
    new Set(releaseIds).size !== releaseIds.length ||
    !plan.snapshots.some((x) => x.id === "service:custodian") ||
    !plan.snapshots.some((x) => x.id === "service:broker")
  )
    throw new Error("release/snapshot inventory invalid");
  for (const [i, p] of plan.proposed.entries()) {
    if (
      p.sequence !== i + 1 ||
      !D4_RESOURCE_KINDS.includes(p.kind) ||
      !plan.snapshots.some((s) => s.id === p.resourceId && s.kind === p.kind) ||
      canonicalHash(p.desiredState) !== p.desiredStateHash ||
      p.readback !== `canonical:${p.desiredStateHash}` ||
      p.successExitCodes.length !== 1 ||
      p.successExitCodes[0] !== 0 ||
      p.requiresElevation !== privileged.has(p.kind) ||
      p.nativeCommand !==
        (privileged.has(p.kind) ? `native:${p.kind}:${p.resourceId}` : null)
    )
      throw new Error("proposal order/binding invalid");
  }
  for (const s of plan.snapshots) {
    if (
      !D4_RESOURCE_KINDS.includes(s.kind) ||
      !["known", "absent"].includes(s.observation) ||
      (s.observation === "known" &&
        (!s.state || canonicalHash(s.state) !== s.stateHash)) ||
      (s.observation === "absent" && (s.state !== null || s.stateHash !== null))
    )
      throw new Error("snapshot prestate invalid");
    const proposed = plan.proposed.some((p) => p.resourceId === s.id);
    if (proposed === (s.restoration === "no_change"))
      throw new Error("snapshot/proposal completeness invalid");
  }
}
function verifyHeldSource(
  mutation: ProposedMutation,
  release: VerifiedD4Release,
  installRoot: string,
): number | null {
  if (!mutation.resourceId.startsWith("release-file:")) return null;
  const path = mutation.resourceId.slice(13),
    handle = release.handles.get(path);
  if (handle === undefined) throw new Error("held source descriptor absent");
  const desired = mutation.desiredState as {
    sha256?: string;
    bytes?: number;
    sourceIdentity?: SourceFileIdentity;
    destination?: string;
    releaseKind?: string;
  };
  const file = release.manifest.files.find((x) => x.path === path);
  if (
    !file ||
    desired.destination !== releaseDestination(path, file.kind, installRoot) ||
    desired.sha256 !== file.sha256 ||
    desired.bytes !== file.bytes
  )
    throw new Error("manifest-to-destination mismatch");
  const stat = fstatSync(handle),
    identity = desired.sourceIdentity;
  if (
    !identity ||
    identity.device !== String(stat.dev) ||
    identity.fileId !== String(stat.ino) ||
    identity.bytes !== stat.size ||
    identity.sha256 !== file.sha256
  )
    throw new Error("held source identity mismatch");
  const bytes = Buffer.alloc(stat.size);
  let offset = 0;
  while (offset < bytes.length) {
    const n = readSync(handle, bytes, offset, bytes.length - offset, offset);
    if (!n) throw new Error("held source short read");
    offset += n;
  }
  if (sha(bytes) !== file.sha256)
    throw new Error("held source rehash mismatch");
  return handle;
}
export function executeTransaction(
  plan: InstallPlan,
  release: VerifiedD4Release,
  expectedAuthorityHashes: string[],
  driver: TransactionDriver,
): TransactionResult {
  validatePlan(plan, release, expectedAuthorityHashes);
  if (!driver.authorize(plan, release))
    throw new Error("driver authorization refused");
  const records: JournalRecord[] = [],
    applied: ProposedMutation[] = [];
  for (const s of plan.snapshots)
    append(records, {
      phase: "snapshot",
      resourceId: s.id,
      result: "ok",
      detail: canonicalContractJson(s),
    });
  for (const mutation of plan.proposed) {
    const heldSourceHandle = verifyHeldSource(
      mutation,
      release,
      plan.target.installRoot,
    );
    const result = driver.apply(mutation, heldSourceHandle);
    if (!mutation.successExitCodes.includes(result.exitCode)) {
      append(records, {
        phase: "apply",
        resourceId: mutation.resourceId,
        result: "failed",
        detail: `native_exit:${result.exitCode}`,
      });
      if (result.atomicNoMutation)
        append(records, {
          phase: "failure-readback",
          resourceId: mutation.resourceId,
          result: "atomic_no_mutation",
          detail: "driver_proved_atomic_no_mutation",
        });
      else {
        const state = driver.readback(mutation);
        append(records, {
          phase: "failure-readback",
          resourceId: mutation.resourceId,
          result: "ok",
          detail: canonicalContractJson(state),
        });
        applied.push(mutation);
      }
      return rollback(plan, driver, records, applied);
    }
    applied.push(mutation);
    append(records, {
      phase: "apply",
      resourceId: mutation.resourceId,
      result: "ok",
      detail: "native_exit:0",
    });
    const state = driver.readback(mutation);
    if (canonicalHash(state) !== mutation.desiredStateHash) {
      append(records, {
        phase: "readback",
        resourceId: mutation.resourceId,
        result: "failed",
        detail: canonicalContractJson(state),
      });
      return rollback(plan, driver, records, applied);
    }
    append(records, {
      phase: "readback",
      resourceId: mutation.resourceId,
      result: "ok",
      detail: mutation.desiredStateHash,
    });
  }
  return {
    status: applied.length ? "installed_stopped_verified" : "no_change",
    records,
    rollbackFailures: [],
    servicesStarted: false,
  };
}
function rollback(
  plan: InstallPlan,
  driver: TransactionDriver,
  records: JournalRecord[],
  applied: ProposedMutation[],
): TransactionResult {
  const failures: string[] = [];
  for (const m of [...applied].reverse()) {
    const s = plan.snapshots.find((x) => x.id === m.resourceId)!;
    const exit = driver.restore(s),
      ok = exit === 0;
    if (!ok) failures.push(s.id);
    append(records, {
      phase: "rollback",
      resourceId: s.id,
      result: ok ? "ok" : "failed",
      detail: `native_exit:${exit};${s.restoration}`,
    });
  }
  return {
    status: failures.length ? "rollback_incomplete" : "rolled_back",
    records,
    rollbackFailures: failures,
    servicesStarted: false,
  };
}
export class MockTransactionDriver implements TransactionDriver {
  readonly calls: string[] = [];
  readonly heldHandles: number[] = [];
  constructor(
    private faults: Readonly<
      Record<string, number | boolean | Record<string, unknown>>
    > = {},
  ) {}
  authorize() {
    return Boolean(this.faults.authorize ?? true);
  }
  apply(m: ProposedMutation, held: number | null) {
    this.calls.push(`apply:${m.resourceId}`);
    if (held !== null) this.heldHandles.push(held);
    return {
      exitCode: Number(this.faults[`apply:${m.resourceId}`] ?? 0),
      atomicNoMutation: Boolean(this.faults[`atomic:${m.resourceId}`] ?? false),
    };
  }
  readback(m: ProposedMutation) {
    this.calls.push(`readback:${m.resourceId}`);
    return (
      (this.faults[`readback:${m.resourceId}`] as
        Record<string, unknown> | undefined) ?? m.desiredState
    );
  }
  restore(s: ResourceSnapshot) {
    this.calls.push(`restore:${s.id}`);
    return Number(this.faults[`restore:${s.id}`] ?? 0);
  }
}
