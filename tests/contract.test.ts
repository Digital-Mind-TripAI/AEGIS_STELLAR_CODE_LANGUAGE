import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

test('v0.1 contract states truthful limits and the mandatory native execution gate', () => {
  const contract = readFileSync(resolve('docs/STELLAR_WINDOWS_X64_V0_1_LANGUAGE_CONTRACT.md'), 'utf8');
  const plan = readFileSync(resolve('native/stellar/v0_1/TRANCHE_PLAN.md'), 'utf8');
  assert.match(contract, /Windows x64 PE\/COFF only/i);
  assert.match(contract, /not a general-purpose language/i);
  assert.match(contract, /official 34 glyphs.*identity.*provenance/is);
  assert.match(contract, /checksum integrity is not authorization/i);
  assert.match(contract, /authenticated Custodian\/Steward-issued capability contract/i);
  assert.match(contract, /OS-enforced native process isolation/i);
  assert.match(contract, /before arbitrary user-defined native execution is enabled/i);
  assert.match(plan, /checksum integrity is not authorization/i);
  assert.match(plan, /authenticated Custodian\/Steward-issued capability contracts/i);
  assert.match(plan, /OS-enforced native process isolation/i);
  assert.match(plan, /blocks arbitrary user-defined native execution/i);
});
