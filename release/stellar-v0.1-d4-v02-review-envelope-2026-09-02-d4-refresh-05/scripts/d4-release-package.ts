import { createHash, sign, verify, type KeyObject } from "node:crypto";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import {
  canonicalContractJson,
  keyIdForPublicKey,
} from "../../../../server/stellar-capability-contract.ts";

export const RELEASE_KINDS = [
  "service",
  "broker",
  "runner",
  "compiler",
  "stdlib",
  "schema",
  "canonical-policy",
  "config",
  "adapter",
  "script",
  "documentation",
  "static-imports",
] as const;
export type ReleaseKind = (typeof RELEASE_KINDS)[number];
export type SigningPolicy = "LAB_SELF_SIGNED" | "EXTERNAL_SIGNER";
export type AuthenticodePolicy =
  "REQUIRE_VALID_EMBEDDED" | "UNSIGNED_REVIEW_ONLY";
export interface D4ReleaseFile {
  path: string;
  kind: ReleaseKind;
  bytes: number;
  sha256: string;
  imports: string[];
  signers: string[];
  authenticodePolicy: AuthenticodePolicy | null;
  nativeInspectionHash: string | null;
}
export interface D4ReleaseManifest {
  schema: "stellar.t7d-release-manifest/v0.2";
  releaseId: string;
  installable: boolean;
  target: { os: "windows"; arch: "x64"; abi: "stellar-win64-v0.1" };
  signingPolicy: SigningPolicy;
  signer: { kid: string; purpose: "aegis-stellar-release" };
  files: D4ReleaseFile[];
}
export interface D4SignedRelease {
  schema: "stellar.t7d-signed-release/v0.2";
  manifest: string;
  signature: string;
}
const HASH = /^sha256:[a-f0-9]{64}$/;
const REL = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
const PE_KINDS = new Set<ReleaseKind>([
  "service",
  "broker",
  "runner",
  "compiler",
]);
const hash = (bytes: Buffer | string) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
export function canonicalReleaseJson(value: unknown): string {
  const walk = (v: unknown, d: number): unknown => {
    if (d > 16) throw new Error("release canonical depth");
    if (v === null || typeof v === "boolean" || typeof v === "string") return v;
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v)) throw new Error("release canonical number");
      return v;
    }
    if (Array.isArray(v)) {
      if (v.length > 512) throw new Error("release canonical array bound");
      return v.map((x) => walk(x, d + 1));
    }
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const p = Object.getPrototypeOf(v);
      if (p !== Object.prototype && p !== null)
        throw new Error("release canonical object");
      const keys = Object.keys(v).sort();
      if (keys.length > 256) throw new Error("release canonical object bound");
      return Object.fromEntries(
        keys.map((k) => [k, walk((v as Record<string, unknown>)[k], d + 1)]),
      );
    }
    throw new Error("release canonical unsupported");
  };
  const text = JSON.stringify(walk(value, 0));
  if (Buffer.byteLength(text) > 1048576)
    throw new Error("release canonical byte bound");
  return text;
}
const heldBytes = (handle: number, size: number) => {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(handle, bytes, offset, size - offset, offset);
    if (count === 0) throw new Error("short held-handle read");
    offset += count;
  }
  return bytes;
};

export function buildUnsignedManifest(input: {
  releaseId: string;
  signingPolicy: SigningPolicy;
  signerKid: string;
  files: Array<{
    path: string;
    kind: ReleaseKind;
    bytes: Buffer;
    imports?: string[];
    signers?: string[];
    authenticodePolicy?: AuthenticodePolicy | null;
    nativeInspectionHash?: string | null;
  }>;
}): D4ReleaseManifest {
  if (
    !/^[A-Za-z0-9._-]{1,128}$/.test(input.releaseId) ||
    !HASH.test(input.signerKid)
  )
    throw new Error("invalid release identity");
  const files = input.files
    .map((file) => {
      if (
        !REL.test(file.path) ||
        file.path.split("/").some((part) => part === "." || part === "..") ||
        !RELEASE_KINDS.includes(file.kind) ||
        file.bytes.length < 1
      )
        throw new Error(`invalid release file: ${file.path}`);
      if (
        (file.imports !== undefined && !Array.isArray(file.imports)) ||
        (file.signers !== undefined && !Array.isArray(file.signers))
      )
        throw new Error(`imports/signers must be arrays: ${file.path}`);
      const imports = [...(file.imports ?? [])].sort(),
        signers = [...(file.signers ?? [])].sort(),
        policy = file.authenticodePolicy ?? null,
        inspectionHash = file.nativeInspectionHash ?? null;
      if (
        PE_KINDS.has(file.kind) &&
        (!imports.length ||
          !signers.length ||
          !policy ||
          !inspectionHash ||
          !HASH.test(inspectionHash))
      )
        throw new Error(`PE imports/signers/inspection missing: ${file.path}`);
      if (
        !PE_KINDS.has(file.kind) &&
        (policy !== null || inspectionHash !== null)
      )
        throw new Error(`non-PE inspection policy invalid: ${file.path}`);
      return {
        path: file.path,
        kind: file.kind,
        bytes: file.bytes.length,
        sha256: hash(file.bytes),
        imports,
        signers,
        authenticodePolicy: policy,
        nativeInspectionHash: inspectionHash,
      };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (new Set(files.map((x) => x.path.toLowerCase())).size !== files.length)
    throw new Error("duplicate or case-colliding release path");
  for (const required of RELEASE_KINDS)
    if (!files.some((x) => x.kind === required))
      throw new Error(`release coverage missing: ${required}`);
  return {
    schema: "stellar.t7d-release-manifest/v0.2",
    releaseId: input.releaseId,
    installable: files
      .filter((x) => PE_KINDS.has(x.kind))
      .every((x) => x.authenticodePolicy === "REQUIRE_VALID_EMBEDDED"),
    target: { os: "windows", arch: "x64", abi: "stellar-win64-v0.1" },
    signingPolicy: input.signingPolicy,
    signer: { kid: input.signerKid, purpose: "aegis-stellar-release" },
    files,
  };
}

/** Signing is injected. This module never creates a key or certificate and never modifies trust. */
export function signManifest(
  manifest: D4ReleaseManifest,
  privateKey: KeyObject,
): D4SignedRelease {
  const canonical = canonicalReleaseJson(manifest);
  return {
    schema: "stellar.t7d-signed-release/v0.2",
    manifest: canonical,
    signature: sign("sha256", Buffer.from(canonical), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url"),
  };
}

export interface NativePeInspection {
  imports: string[];
  signers: string[];
  authenticodePolicy: AuthenticodePolicy;
  inspectionHash: string;
  nativeInspected: true;
}
export interface PackageInspection {
  pe(path: string): Promise<NativePeInspection>;
  streams(path: string): Promise<string[]>;
  acl(
    path: string,
  ): Promise<"reviewed" | "unreviewed" | "unknown_requires_elevation">;
}
export interface VerifiedD4Release {
  manifest: D4ReleaseManifest;
  root: string;
  handles: Map<string, number>;
  releaseHash: string;
  close(): void;
}

function packageRoot(path: string) {
  if (
    !isAbsolute(path) ||
    path.startsWith("\\\\") ||
    /^\\\\\?\\UNC\\/i.test(path) ||
    path.slice(2).includes(":")
  )
    throw new Error("path/ADS/UNC refused");
  if (lstatSync(path).isSymbolicLink())
    throw new Error("PackageRoot reparse refused");
  const root = realpathSync.native(path);
  let cursor = root;
  for (;;) {
    const s = lstatSync(cursor);
    if (s.isSymbolicLink()) throw new Error("reparse ancestor refused");
    const parent = resolve(cursor, "..");
    if (parent === cursor) break;
    cursor = parent;
  }
  return root;
}
function confined(root: string, rel: string) {
  if (!REL.test(rel) || rel.includes(":")) throw new Error("path/ADS refused");
  const candidate = resolve(root, ...rel.split("/"));
  const delta = relative(root, candidate);
  if (
    !delta ||
    delta === ".." ||
    delta.startsWith(`..${sep}`) ||
    isAbsolute(delta)
  )
    throw new Error("path escape refused");
  let cursor = root;
  for (const part of rel.split("/").slice(0, -1)) {
    cursor = resolve(cursor, part);
    if (lstatSync(cursor).isSymbolicLink())
      throw new Error("reparse ancestor refused");
  }
  const before = lstatSync(candidate);
  if (before.isSymbolicLink() || before.nlink !== 1 || !before.isFile())
    throw new Error("reparse/hardlink/non-file refused");
  const real = realpathSync.native(candidate),
    realDelta = relative(root, real);
  if (
    realDelta === ".." ||
    realDelta.startsWith(`..${sep}`) ||
    isAbsolute(realDelta)
  )
    throw new Error("resolved path escape refused");
  return { candidate, real, before };
}
export async function verifySignedRelease(
  rootPath: string,
  envelope: D4SignedRelease,
  keyLookup: (kid: string) => KeyObject | undefined,
  inspection: PackageInspection,
): Promise<VerifiedD4Release> {
  if (
    envelope.schema !== "stellar.t7d-signed-release/v0.2" ||
    !/^[A-Za-z0-9_-]+$/.test(envelope.signature)
  )
    throw new Error("invalid signed envelope");
  const parsed = JSON.parse(envelope.manifest) as D4ReleaseManifest;
  if (canonicalReleaseJson(parsed) !== envelope.manifest)
    throw new Error("noncanonical manifest");
  if (
    parsed.schema !== "stellar.t7d-release-manifest/v0.2" ||
    !/^[A-Za-z0-9._-]{1,128}$/.test(parsed.releaseId) ||
    !["LAB_SELF_SIGNED", "EXTERNAL_SIGNER"].includes(parsed.signingPolicy) ||
    typeof parsed.installable !== "boolean" ||
    parsed.target?.os !== "windows" ||
    parsed.target?.arch !== "x64" ||
    parsed.target?.abi !== "stellar-win64-v0.1" ||
    parsed.signer?.purpose !== "aegis-stellar-release" ||
    !HASH.test(parsed.signer?.kid ?? "") ||
    !Array.isArray(parsed.files) ||
    parsed.files.length < RELEASE_KINDS.length ||
    parsed.files.length > 256
  )
    throw new Error("manifest structure invalid");
  let prior = "";
  const folded = new Set<string>();
  for (const file of parsed.files) {
    const lower = file.path.toLowerCase();
    if (
      folded.has(lower) ||
      !REL.test(file.path) ||
      file.path.split("/").some((x) => x === "." || x === "..") ||
      file.path <= prior ||
      !RELEASE_KINDS.includes(file.kind) ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes < 1 ||
      !HASH.test(file.sha256) ||
      !Array.isArray(file.imports) ||
      file.imports.length > 512 ||
      !Array.isArray(file.signers) ||
      file.signers.length > 32 ||
      ![...file.imports].every(
        (x) => typeof x === "string" && x.length <= 256,
      ) ||
      ![...file.signers].every(
        (x) => typeof x === "string" && x.length <= 256,
      ) ||
      canonicalContractJson(file.imports) !==
        canonicalContractJson([...file.imports].sort()) ||
      canonicalContractJson(file.signers) !==
        canonicalContractJson([...file.signers].sort()) ||
      (PE_KINDS.has(file.kind) &&
        (!file.imports.length ||
          !file.signers.length ||
          !file.authenticodePolicy ||
          !file.nativeInspectionHash)) ||
      (!PE_KINDS.has(file.kind) &&
        (file.authenticodePolicy !== null ||
          file.nativeInspectionHash !== null)) ||
      (file.nativeInspectionHash !== null &&
        !HASH.test(file.nativeInspectionHash))
    )
      throw new Error("manifest file structure invalid");
    prior = file.path;
    folded.add(lower);
  }
  if (
    parsed.installable !==
    parsed.files
      .filter((x) => PE_KINDS.has(x.kind))
      .every((x) => x.authenticodePolicy === "REQUIRE_VALID_EMBEDDED")
  )
    throw new Error("installable policy mismatch");
  for (const required of RELEASE_KINDS)
    if (!parsed.files.some((x) => x.kind === required))
      throw new Error(`release coverage missing: ${required}`);
  const key = keyLookup(parsed.signer.kid);
  if (
    !key ||
    keyIdForPublicKey(key) !== parsed.signer.kid ||
    !verify(
      "sha256",
      Buffer.from(envelope.manifest),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(envelope.signature, "base64url"),
    )
  )
    throw new Error("bad signer/signature");
  const root = packageRoot(rootPath),
    handles = new Map<string, number>();
  try {
    for (const file of parsed.files) {
      const item = confined(root, file.path),
        handle = openSync(item.real, "r"),
        after = fstatSync(handle);
      if (
        after.dev !== item.before.dev ||
        after.ino !== item.before.ino ||
        after.size !== item.before.size
      ) {
        closeSync(handle);
        throw new Error("file identity race");
      }
      handles.set(file.path, handle);
      const bytes = heldBytes(handle, after.size);
      if (bytes.length !== file.bytes || hash(bytes) !== file.sha256)
        throw new Error(`bad hash/length: ${file.path}`);
      const streams = (await inspection.streams(item.real)).sort();
      if (canonicalContractJson(streams) !== canonicalContractJson(["::$DATA"]))
        throw new Error(`ADS refused: ${file.path}`);
      if (PE_KINDS.has(file.kind)) {
        const pe = await inspection.pe(item.real);
        if (
          pe.nativeInspected !== true ||
          canonicalContractJson([...pe.imports].sort()) !==
            canonicalContractJson(file.imports) ||
          canonicalContractJson([...pe.signers].sort()) !==
            canonicalContractJson(file.signers) ||
          pe.authenticodePolicy !== file.authenticodePolicy ||
          pe.inspectionHash !== file.nativeInspectionHash
        )
          throw new Error(`native imports/signer mismatch: ${file.path}`);
      }
      if ((await inspection.acl(item.real)) !== "reviewed")
        throw new Error(`ACL unknown/unreviewed: ${file.path}`);
      const final = fstatSync(handle);
      if (
        final.dev !== after.dev ||
        final.ino !== after.ino ||
        final.size !== after.size ||
        hash(heldBytes(handle, final.size)) !== file.sha256
      )
        throw new Error(`post-inspection identity/hash mismatch: ${file.path}`);
    }
    return {
      manifest: parsed,
      root,
      handles,
      releaseHash: hash(envelope.manifest),
      close() {
        for (const h of handles.values()) closeSync(h);
        handles.clear();
      },
    };
  } catch (e) {
    for (const h of handles.values()) closeSync(h);
    throw e;
  }
}
