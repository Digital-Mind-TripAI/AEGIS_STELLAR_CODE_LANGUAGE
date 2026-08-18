import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

const root = resolve('native/stellar/v0_1');
const scratch = mkdtempSync(join(tmpdir(), 'stellar-v01-tranche1-'));
const executable = join(scratch, 'stellar.exe');
const fixtureRoot = join(root, 'tests/fixtures/tranche1');

before(() => execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(root, 'tools/build-cli.ps1'), '-Output', executable], { cwd: resolve('.'), stdio: 'pipe' }));
after(() => rmSync(scratch, { recursive: true, force: true }));
const run = (args: string[]) => spawnSync(executable, args, { cwd: resolve('.'), encoding: 'utf8' });
const inspect = (name: string) => {
  const result = run(['inspect', join(fixtureRoot, name)]);
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  return JSON.parse(result.stdout);
};

const positiveCorpus = [
  'scalar-control.stellar', 'memory-layout.stellar', 'control-variants.stellar',
  'memory-layout-2.stellar', 'memory-layout-3.stellar', 'control-calls.stellar',
];

test('six structurally distinct programs type-check through unified AST/HIR/MIR', () => {
  for (const name of positiveCorpus) {
    const result = inspect(name);
    assert.equal(result.profile, 'stellar-windows-x64-v0.1');
    assert.ok(result.ast.declarations.length >= 2);
    assert.ok(result.hir.operations.length > 0);
    assert.ok(result.mir.blocks.length > 0);
    assert.deepEqual(result.effects.required, []);
    assert.equal(result.executionEnabled, false);
  }
});

test('positive corpus supplies at least three programs per type, memory, and control family', () => {
  const analyses = new Map(positiveCorpus.map((name) => [name, inspect(name)]));
  assert.ok(analyses.size >= 3, 'fixed-width type family');
  assert.equal(['memory-layout.stellar', 'memory-layout-2.stellar', 'memory-layout-3.stellar'].filter((name) => Object.keys(analyses.get(name).layouts).length > 0).length, 3);
  assert.equal(['scalar-control.stellar', 'control-variants.stellar', 'control-calls.stellar'].filter((name) => analyses.get(name).mir.blocks.some((block: any) => block.loopProof || block.terminator === 'branch')).length, 3);
  assert.equal(['scalar-control.stellar', 'memory-layout.stellar', 'control-calls.stellar'].filter((name) => analyses.get(name).hir.operations.some((op: any) => op.op === 'call')).length, 3);
  assert.ok(positiveCorpus.filter((name) => analyses.get(name).hir.operations.some((op: any) => op.op === 'checked_add')).length >= 3);
  assert.ok(positiveCorpus.filter((name) => analyses.get(name).hir.operations.some((op: any) => op.op === 'wrapping_add')).length >= 3);
});

test('scalar types, explicit conversions, checked and wrapping arithmetic are typed', () => {
  const scalar = inspect('scalar-control.stellar');
  assert.deepEqual(scalar.types.fixedWidth, ['bool', 'i32', 'i64', 'u32', 'u64', 'f64']);
  assert.ok(scalar.hir.operations.some((op: any) => op.op === 'convert' && op.type === 'i64'));
  assert.ok(scalar.hir.operations.some((op: any) => op.op === 'checked_add'));
  const control = inspect('control-variants.stellar');
  assert.ok(control.hir.operations.some((op: any) => op.op === 'wrapping_add' && op.type === 'u64'));
});

test('deterministic layouts cover three structs, arrays and bounded caller-owned slices', () => {
  const result = inspect('memory-layout.stellar');
  assert.deepEqual(result.layouts.Sample, {
    size: 40, alignment: 8,
    fields: [
      { name: 'active', type: 'bool', offset: 0 },
      { name: 'count', type: 'i32', offset: 4 },
      { name: 'total', type: 'i64', offset: 8 },
      { name: 'weights', type: 'array(f64,3)', offset: 16 },
    ],
  });
  assert.deepEqual(result.layouts.Packet, { size: 20, alignment: 4, fields: [{ name: 'code', type: 'u32', offset: 0 }, { name: 'values', type: 'array(i32,4)', offset: 4 }] });
  assert.deepEqual(result.layouts.Wide, { size: 16, alignment: 8, fields: [{ name: 'first', type: 'u64', offset: 0 }, { name: 'second', type: 'f64', offset: 8 }] });
  assert.ok(result.trace.some((entry: any) => entry.kind === 'slice' && entry.bound === 16 && entry.abi === 'caller-owned(ptr,len)'));
  assert.ok(result.trace.some((entry: any) => entry.kind === 'stack-slot'));
  assert.ok(result.trace.some((entry: any) => entry.kind === 'stack-byte-layout' && typeof entry.stackOffset === 'number'));
  assert.ok(result.trace.some((entry: any) => entry.kind === 'stack-frame' && entry.alignment === 16));
});

test('branches, compiler-proven loops, scoped break/continue and Result status lower to MIR', () => {
  const result = inspect('control-variants.stellar');
  assert.ok(result.mir.blocks.some((block: any) => block.terminator === 'branch'));
  assert.ok(result.mir.blocks.some((block: any) => block.loopProof?.maximum === 8));
  assert.ok(result.mir.blocks.some((block: any) => block.terminator === 'break'));
  assert.ok(result.mir.blocks.some((block: any) => block.terminator === 'continue'));
  assert.ok(result.hir.operations.some((op: any) => op.op === 'result_err'));
  assert.ok(result.mir.blocks.some((block: any) => block.terminator === 'overflow-check'));
});

test('trace preserves source spans, typed ops, layout offsets and empty effects', () => {
  const result = inspect('memory-layout.stellar');
  assert.ok(result.trace.every((entry: any) => entry.span?.start?.line > 0));
  assert.ok(result.trace.some((entry: any) => typeof entry.structOffset === 'number'));
  assert.deepEqual(result.effects, { required: [], imports: [] });
  assert.deepEqual(result.memoryModel, { heap: false, garbageCollector: false, locals: 'stack', sliceOwnership: 'caller' });
  assert.equal(result.homeostasis, 'NOT_EVALUATED');
});

test('typed inspect output is byte-deterministic across repeated compilation', () => {
  const fixture = join(fixtureRoot, 'control-calls.stellar');
  const first = run(['inspect', fixture]);
  const second = run(['inspect', fixture]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(second.stdout, first.stdout);
});

const negativeCases: Array<[string, string, RegExp]> = [
  ['implicit-narrowing', 'function bad ( wide / i64 ) / Result ( i32 ) ( let small / i32 ( wide ) · return ok ( small ) · ) ·', /S2004/],
  ['recursion', 'function again ( value / i32 ) / Result ( i32 ) ( let next / i32 ( try_value ( again ( value ) ) ) · return ok ( next ) · ) ·', /S2008/],
  ['unbounded-loop', 'function bad ( limit / i32 ) / Result ( i32 ) ( loop i / i32 ( from: 0, max: limit ) ( continue · ) · return ok ( 0 ) · ) ·', /S3002/],
  ['invalid-array-layout', 'struct Bad ( items / array ( i64, 0 ) ) · function main ( ) / Result ( i32 ) ( return ok ( 0 ) · ) ·', /S3001/],
  ['array-bounds', 'function bad ( ) / Result ( i32 ) ( let values / array ( i32, 3 ) · return ok ( index ( values, 3 ) ) · ) ·', /S3004/],
  ['break-outside-loop', 'function bad ( ) / Result ( i32 ) ( break · return ok ( 0 ) · ) ·', /S3003/],
  ['undeclared-effect', 'function bad ( ) / Result ( i32 ) ( ConsoleWrite ( 1 ) · return ok ( 0 ) · ) ·', /S4003/],
  ['missing-result', 'function bad ( value / i32 ) / Result ( i32 ) ( let copy / i32 ( value ) · ) ·', /S2006/],
  ['branch-scope-leak', 'function bad ( flag / bool ) / Result ( i32 ) ( if equal ( flag, true ) ( let hidden / i32 ( 1 ) · ) ~ otherwise ( let other / i32 ( 2 ) · ) · return ok ( hidden ) · ) ·', /S2003/],
  ['literal-overflow', 'function bad ( ) / Result ( i32 ) ( return ok ( 2147483648 ) · ) ·', /S2007/],
  ['malformed-number', 'function bad ( ) / Result ( f64 ) ( return ok ( 1.2.3 ) · ) ·', /S1002/],
];

for (const [name, source, expected] of negativeCases) {
  test(`refuses ${name}`, () => {
    const file = join(scratch, `${name}.stellar`);
    writeFileSync(file, source, 'utf8');
    const result = run(['check', file, '--diagnostic-format', 'json']);
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, expected);
  });
}
