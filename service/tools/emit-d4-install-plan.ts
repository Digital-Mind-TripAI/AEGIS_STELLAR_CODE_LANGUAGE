import { createHash, createPublicKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import {
  canonicalContractJson,
  keyIdForPublicKey,
} from "../../../../../server/stellar-capability-contract.ts";
import {
  planOfflineInstall,
  type ReleaseInstallFile,
} from "../d4-installer-model.ts";
import {
  canonicalReleaseJson,
  verifySignedRelease,
  type D4SignedRelease,
  type NativePeInspection,
  type PackageInspection,
} from "../d4-release-package.ts";
const [rootArg, keyArg, pinArg] = process.argv.slice(2);
if (!rootArg || !keyArg || !pinArg)
  throw new Error(
    "usage: emit-d4-install-plan <PackageRoot> <ExternalAuthorityPem> <ExternalPinJson>",
  );
const root = realpathSync.native(resolve(rootArg)),
  keyPath = realpathSync.native(resolve(keyArg)),
  pinPath = realpathSync.native(resolve(pinArg));
for (const authorityPath of [keyPath, pinPath]) {
  if (!isAbsolute(authorityPath)) {
    throw new Error("authority path must be absolute");
  }
  const delta = relative(root, authorityPath);
  if (delta === "" || (!delta.startsWith(`..${sep}`) && delta !== ".."))
    throw new Error("authority must remain outside PackageRoot");
}
const hash = (b: Buffer | string) =>
  `sha256:${createHash("sha256").update(b).digest("hex")}`;
const keyBytes = readFileSync(keyPath),
  pinBytes = readFileSync(pinPath),
  pinText = pinBytes.toString("utf8").trimEnd(),
  pin = JSON.parse(pinText) as {
    schema: string;
    keySha256: string;
    kid: string;
    purpose: string;
  };
if (
  canonicalContractJson(pin) !== pinText ||
  pin.schema !== "stellar.t7d-external-authority-pin/v0.1" ||
  pin.keySha256 !== hash(keyBytes) ||
  pin.purpose !== "offline-review-envelope-only"
)
  throw new Error("external authority pin invalid");
const key = createPublicKey(keyBytes);
if (keyIdForPublicKey(key) !== pin.kid)
  throw new Error("external authority kid mismatch");
const manifestText = readFileSync(
    resolve(root, "release-manifest.v0.2.canonical.json"),
    "utf8",
  ),
  envelopeText = readFileSync(
    resolve(root, "release-envelope.v0.2.canonical.json"),
    "utf8",
  ),
  envelope = JSON.parse(envelopeText) as D4SignedRelease;
if (
  canonicalReleaseJson(envelope) !== envelopeText ||
  envelope.manifest !== manifestText
)
  throw new Error("release envelope bytes are not canonical/bound");
const helper = resolve(import.meta.dirname, "inspect-d4-package-file.ps1");
const peEvidence = (path: string): NativePeInspection => {
  const sidecar = resolve(
      root,
      "inspection",
      `${path.split(/[\\/]/).at(-1)}.native-inspection.json`,
    ),
    text = readFileSync(sidecar, "utf8").trimEnd(),
    value = JSON.parse(text) as {
      imports: string[];
      signers: string[];
      authenticodePolicy: NativePeInspection["authenticodePolicy"];
    };
  return {
    imports: value.imports,
    signers: value.signers,
    authenticodePolicy: value.authenticodePolicy,
    inspectionHash: hash(text),
    nativeInspected: true,
  };
};
const readbackCache = new Map<
  string,
  { streams: string[]; aclReviewed: boolean }
>();
const osReadback = (path: string) => {
  const existing = readbackCache.get(path);
  if (existing) return existing;
  const observed = JSON.parse(
    execFileSync("pwsh.exe", ["-NoProfile", "-File", helper, "-Path", path], {
      encoding: "utf8",
      windowsHide: true,
    }),
  ) as { streams: string[]; aclReviewed: boolean };
  readbackCache.set(path, observed);
  return observed;
};
const inspection: PackageInspection = {
  pe: async (path) => peEvidence(path),
  streams: async (path) =>
    osReadback(path).streams.map((stream) =>
      stream === ":$DATA" ? "::$DATA" : stream,
    ),
  acl: async (path) =>
    osReadback(path).aclReviewed ? "reviewed" : "unreviewed",
};
const verified = await verifySignedRelease(
  root,
  envelope,
  (kid) => (kid === pin.kid ? key : undefined),
  inspection,
);
try {
  const allowedMetadata = new Set([
      "LAB-REVIEW-SIGNER-PUBLIC.pem",
      "REVIEW-ENVELOPE-RECEIPT.canonical.json",
      "release-envelope.v0.2.canonical.json",
      "release-manifest.v0.2.canonical.json",
    ]),
    declared = new Set(
      verified.manifest.files.map((x) => x.path.toLowerCase()),
    );
  for (const item of readdirSync(root, {
    recursive: true,
    withFileTypes: true,
  })) {
    if (!item.isFile()) continue;
    const rel = relative(root, resolve(item.parentPath, item.name))
      .split(sep)
      .join("/");
    if (!declared.has(rel.toLowerCase()) && !allowedMetadata.has(rel))
      throw new Error(`undeclared release file: ${rel}`);
  }
  const files: ReleaseInstallFile[] = verified.manifest.files.map((file) => {
    const handle = verified.handles.get(file.path);
    if (handle === undefined) throw new Error("verified handle absent");
    const stat = fstatSync(handle);
    return {
      path: file.path,
      sha256: file.sha256,
      bytes: file.bytes,
      kind: file.kind,
      sourceIdentity: {
        device: String(stat.dev),
        fileId: String(stat.ino),
        bytes: stat.size,
        sha256: file.sha256,
        retainedHandle: true,
      },
    };
  });
  const authorityHashes = [hash(keyBytes), hash(pinBytes), hash(envelopeText)];
  const plan = planOfflineInstall({
    releaseHash: verified.releaseHash,
    authorityHashes,
    releaseFiles: files,
  });
  const closure = JSON.parse(
    readFileSync(
      resolve(root, "runtime", "runtime-dependency-closure.canonical.json"),
      "utf8",
    ),
  ) as { closed: boolean; installedPaths: string[] };
  const plannedDestinations = new Set(
    plan.proposed
      .filter((mutation) => mutation.kind === "file")
      .map((mutation) =>
        String(mutation.desiredState.destination).toLowerCase(),
      ),
  );
  if (
    closure.closed !== true ||
    !closure.installedPaths.length ||
    closure.installedPaths.some(
      (destination) => !plannedDestinations.has(destination.toLowerCase()),
    )
  )
    throw new Error(
      "runtime dependency closure is not realized by InstallPlan",
    );
  process.stdout.write(canonicalReleaseJson(plan));
} finally {
  verified.close();
}
