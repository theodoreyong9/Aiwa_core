import { test } from 'node:test';
import assert from 'node:assert/strict';
import { identityCostFromCommitments } from '../src/identity-cost.js';
import { computeCausalTick } from '../src/causal-tick.js';
import { initialMirrorState } from '../src/mirror.js';

test('committed capital b (whole units) becomes the lamport weight the causal tick reads; nothing committed weighs nothing', () => {
  const state = identityCostFromCommitments({ a: { b: 2 }, b: { b: 0 }, c: { b: 0.5 }, d: {} });
  assert.deepEqual(Object.keys(state.registered).sort(), ['a', 'c']);
  assert.equal(state.registered.a.burnedLamports, 2_000_000_000);
  assert.equal(state.registered.c.burnedLamports, 500_000_000);
  assert.deepEqual(identityCostFromCommitments(undefined), { registered: {}, usedSignatures: {} });
});

test('the causal tick accepts the state as it is (no observers: still an honest bottom)', async () => {
  const state = identityCostFromCommitments({ a: { b: 1 } });
  assert.equal(await computeCausalTick(initialMirrorState(), state, [], 'target'), null);
});
