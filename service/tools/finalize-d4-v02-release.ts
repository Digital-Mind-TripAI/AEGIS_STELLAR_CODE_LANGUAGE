import { createHash, generateKeyPairSync } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { canonicalContractJson, keyIdForPublicKey } from '../../../../../server/stellar-capability-contract.ts';
import { buildUnsignedManifest, canonicalReleaseJson, signManifest, type AuthenticodePolicy, type ReleaseKind } from '../d4-release-package.ts';

type InventoryFile = { path: string; kind: ReleaseKind; imports: string[]; signers: string[]; authenticodePolicy: AuthenticodePolicy | null; nativeInspectionHash: string | null };
type Inventory = { releaseId: string; files: InventoryFile[] };
type AcceptedRuntimeBinding = {
  schema: 'stellar.t7b-target-host-acceptance/v0.1'; status: 'passed'; executionClass: 'FIXED_SECURITY_PROBE_ONLY';
  securityGate: { arbitraryCodeLoaded: false; s7001StellarExecutionClosed: true; serverIntegrated: false };
  bindings: { brokerSha256: string; runnerSha256: string };
};

const [rootArg, inputArg, expectedBrokerSha256, expectedRunnerSha256] = process.argv.slice(2);
if (!rootArg || !inputArg || !expectedBrokerSha256 || !expectedRunnerSha256) throw new Error('usage: finalize <root> <inventory> <expected-broker-sha256> <expected-runner-sha256>');
const root = resolve(rootArg);
const finalGateError = (kind: 'broker' | 'runner', reason: string) => new Error(`D4_T7B_FINAL_${kind.toUpperCase()}_${reason}`);
const inventoryError = (reason: string) => new Error(`D4_T7B_FINAL_INVENTORY_${reason}`);
const acceptancePath = 'runtime/t7b-target-host-acceptance.json';

function assertReparseFree(path: string, label: string): void {
  if (lstatSync(path).isSymbolicLink()) throw inventoryError(`${label}_REPARSE_PATH`);
}

function confinedPath(value: string, label: string): string {
  const candidate = resolve(isAbsolute(value) ? value : resolve(root, value));
  const pathFromRoot = relative(root, candidate);
  if (!pathFromRoot || pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`) || isAbsolute(pathFromRoot)) throw inventoryError(`${label}_OUTSIDE_ROOT`);
  assertReparseFree(root, 'ROOT');
  let current = root;
  for (const segment of pathFromRoot.split(sep)) { current = resolve(current, segment); assertReparseFree(current, label); }
  return candidate;
}

function inventoryPath(path: string): string {
  if (!path || path.includes('\\') || path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) throw inventoryError('PATH_INVALID');
  return confinedPath(path, 'ENTRY');
}

function binding(value: unknown, kind: 'broker' | 'runner', malformed = false): string {
  if (typeof value !== 'string') throw finalGateError(kind, malformed ? 'ACCEPTANCE_BINDING_INVALID' : 'HASH_INVALID');
  const normalized = value.startsWith('sha256:') ? value : `sha256:${value}`;
  if (!/^sha256:[0-9a-f]{64}$/.test(normalized)) throw finalGateError(kind, malformed ? 'ACCEPTANCE_BINDING_INVALID' : 'HASH_INVALID');
  return normalized;
}

function readAcceptedRuntimeBinding(bytes: Buffer): AcceptedRuntimeBinding {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { throw inventoryError('ACCEPTANCE_JSON_INVALID'); }
  if (!value || typeof value !== 'object') throw inventoryError('ACCEPTANCE_SCHEMA_INVALID');
  const record = value as Partial<AcceptedRuntimeBinding>;
  if (record.schema !== 'stellar.t7b-target-host-acceptance/v0.1' || record.status !== 'passed' || record.executionClass !== 'FIXED_SECURITY_PROBE_ONLY') throw inventoryError('ACCEPTANCE_SCHEMA_INVALID');
  if (!record.securityGate || record.securityGate.arbitraryCodeLoaded !== false || record.securityGate.s7001StellarExecutionClosed !== true || record.securityGate.serverIntegrated !== false) throw inventoryError('ACCEPTANCE_SCHEMA_INVALID');
  if (!record.bindings || typeof record.bindings !== 'object') throw inventoryError('ACCEPTANCE_SCHEMA_INVALID');
  binding(record.bindings.brokerSha256, 'broker', true);
  binding(record.bindings.runnerSha256, 'runner', true);
  return record as AcceptedRuntimeBinding;
}

const inputPath = confinedPath(inputArg, 'INPUT');
const input = JSON.parse(readFileSync(inputPath, 'utf8')) as Inventory;
if (!input || typeof input.releaseId !== 'string' || !Array.isArray(input.files)) throw inventoryError('SCHEMA_INVALID');
const expectedBindings = { broker: binding(expectedBrokerSha256, 'broker'), runner: binding(expectedRunnerSha256, 'runner') };
const requiredRuntimeEntries = [
  { path: 'bin/stellar-t7b-sandbox.exe', kind: 'broker' as const, sha256: expectedBindings.broker },
  { path: 'bin/stellar-t7b-fixed-probe.exe', kind: 'runner' as const, sha256: expectedBindings.runner },
] as const;
const acceptanceEntries = input.files.filter((file) => file.path === acceptancePath);
if (acceptanceEntries.length === 0) throw inventoryError('ACCEPTANCE_ENTRY_MISSING');
if (acceptanceEntries.length > 1) throw inventoryError('ACCEPTANCE_ENTRY_DUPLICATE');
if (acceptanceEntries[0].kind !== 'canonical-policy') throw inventoryError('ACCEPTANCE_ENTRY_WRONG_KIND');
for (const required of requiredRuntimeEntries) {
  const entries = input.files.filter((file) => file.path === required.path);
  if (entries.length === 0) throw finalGateError(required.kind, 'ENTRY_MISSING');
  if (entries.length > 1) throw finalGateError(required.kind, 'ENTRY_DUPLICATE');
  if (entries[0].kind !== required.kind) throw finalGateError(required.kind, 'ENTRY_WRONG_KIND');
}
const payload = input.files.map((file) => ({ file, bytes: readFileSync(inventoryPath(file.path)) }));
const acceptedBindings = readAcceptedRuntimeBinding(payload.find(({ file }) => file.path === acceptancePath)!.bytes).bindings;
for (const required of requiredRuntimeEntries) {
  const accepted = binding(acceptedBindings[`${required.kind}Sha256`], required.kind, true);
  if (accepted !== required.sha256) throw finalGateError(required.kind, 'ACCEPTANCE_BINDING_MISMATCH');
  const { bytes } = payload.find(({ file }) => file.path === required.path)!;
  if (`sha256:${createHash('sha256').update(bytes).digest('hex')}` !== accepted) throw finalGateError(required.kind, 'HASH_MISMATCH');
}

const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const kid = keyIdForPublicKey(pair.publicKey);
const manifest = buildUnsignedManifest({ releaseId: input.releaseId, signingPolicy: 'LAB_SELF_SIGNED', signerKid: kid, files: payload.map(({ file, bytes }) => ({ ...file, bytes })) });
const envelope = signManifest(manifest, pair.privateKey), manifestText = canonicalReleaseJson(manifest), envelopeText = canonicalReleaseJson(envelope), publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
writeFileSync(resolve(root, 'release-manifest.v0.2.canonical.json'), manifestText); writeFileSync(resolve(root, 'release-envelope.v0.2.canonical.json'), envelopeText); writeFileSync(resolve(root, 'LAB-REVIEW-SIGNER-PUBLIC.pem'), publicPem);
const hash = (value: Buffer | string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const receipt = { schema: 'stellar.t7d-review-envelope-receipt/v0.1', installable: manifest.installable, releaseHash: hash(manifestText), envelopeHash: hash(envelopeText), publicKeyHash: hash(publicPem), signerKid: kid, certificateMinted: false, trustModified: false, privateKeyRetained: false, purpose: 'offline-review-envelope-only' };
writeFileSync(resolve(root, 'REVIEW-ENVELOPE-RECEIPT.canonical.json'), canonicalContractJson(receipt)); process.stdout.write(canonicalContractJson(receipt));
