import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

test('D3 verifier derives the emitted evidence path from its requested evidence root', () => {
  const verifier = readFileSync(resolve('native/stellar/v0_1/service/tools/verify-d3-offline.ps1'), 'utf8');

  assert.match(verifier, /\$path=Join-Path \$resolvedEvidence 't7d-d3-offline-build\.json'/);
  assert.match(verifier, /\[IO\.Path\]::GetRelativePath\(\$repoRoot,\$path\)/);
  assert.match(verifier, /\$canonicalEvidencePath=\$relativeEvidencePath\.Replace\(/);
  assert.match(verifier, /canonicalEvidencePath=\$canonicalEvidencePath/);
  assert.doesNotMatch(verifier, /canonicalEvidencePath='native\/stellar\/v0_1\/evidence\/d3-v02-build/);
});

test('D3 verifier requires a fresh explicit evidence root before any filesystem write', () => {
  const verifier = readFileSync(resolve('native/stellar/v0_1/service/tools/verify-d3-offline.ps1'), 'utf8');

  assert.match(verifier, /\[Parameter\(Mandatory=\$true\)\]\s*\[ValidateNotNullOrWhiteSpace\(\)\]\s*\[string\]\$EvidenceDirectory/);
  assert.doesNotMatch(verifier, /\$EvidenceDirectory\s*=/);
  assert.match(verifier, /if\(Test-Path -LiteralPath \$resolvedEvidence\)\{throw 'T7D_D3_EVIDENCE_DIRECTORY_ALREADY_EXISTS'\}/);

  const freshRootGuard = verifier.indexOf("if(Test-Path -LiteralPath $resolvedEvidence){throw 'T7D_D3_EVIDENCE_DIRECTORY_ALREADY_EXISTS'}");
  const firstFilesystemWrite = verifier.indexOf('New-Item -ItemType Directory -Path $resolvedEvidence -Force');
  assert.ok(freshRootGuard >= 0, 'fresh evidence-root guard must be present');
  assert.ok(firstFilesystemWrite >= 0, 'verifier must create the requested fresh evidence root');
  assert.ok(freshRootGuard < firstFilesystemWrite, 'fresh evidence-root guard must run before any evidence-root write');
});
