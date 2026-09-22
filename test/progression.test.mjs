import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeVdfChain, vdfSeed, verifyVdfChain } from '../src/vdf.js';
import { initialProgressionState, applyProgressionEvent, materializeProgression } from '../src/progression.js';

async function progressionPayload(domain, epoch, previousOutput = 'genesis', iterations = 50) {
  const seed = vdfSeed(domain, previousOutput);
  const vdfOutput = await computeVdfChain(seed, iterations);
  return { type: 'progression', domain, epoch, vdfIterations: iterations, vdfOutput };
}

test('first transition is accepted', async () => {
  const payload = await progressionPayload('d', 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains.d.epoch, 1);
  assert.equal(state.rejections.length, 0);
});

test('skipping an epoch is rejected', async () => {
  const payload = await progressionPayload('d', 2);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains.d, undefined);
  assert.equal(state.rejections.length, 1);
});

test('a transition not chained to the last accepted one is rejected', async () => {
  let state = initialProgressionState();
  const p1 = await progressionPayload('d', 1);
  state = await applyProgressionEvent(state, { id: 'e1', parents: [], payload: p1 });
  const p2 = await progressionPayload('d', 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2', parents: [], payload: p2 });
  assert.equal(state.domains.d.epoch, 1);
});

test('a forked competing transition at the same epoch is rejected', async () => {
  let state = initialProgressionState();
  const p1 = await progressionPayload('d', 1);
  state = await applyProgressionEvent(state, { id: 'e1', parents: [], payload: p1 });
  const p2a = await progressionPayload('d', 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2a', parents: ['e1'], payload: p2a });
  const p2b = await progressionPayload('d', 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2b', parents: ['e1'], payload: p2b });
  assert.equal(state.domains.d.lastId, 'e2a');
});

test('SECURITY: a transition with no real VDF proof is rejected', async () => {
  const state = await applyProgressionEvent(initialProgressionState(), {
    id: 'e1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1, vdfIterations: 50, vdfOutput: null },
  });
  assert.equal(state.domains.d, undefined);
});

test('SECURITY: a fabricated VDF output is rejected', async () => {
  const state = await applyProgressionEvent(initialProgressionState(), {
    id: 'e1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1, vdfIterations: 50, vdfOutput: 'f'.repeat(64) },
  });
  assert.equal(state.domains.d, undefined);
});

test('SECURITY: a real chain computed for fewer iterations than claimed is rejected', async () => {
  const seed = vdfSeed('d', 'genesis');
  const shortcut = await computeVdfChain(seed, 40);
  const state = await applyProgressionEvent(initialProgressionState(), {
    id: 'e1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1, vdfIterations: 50, vdfOutput: shortcut },
  });
  assert.equal(state.domains.d, undefined);
});

test('SECURITY: a VDF proof computed for a different domain cannot be reused', async () => {
  const otherOutput = await computeVdfChain(vdfSeed('other', 'genesis'), 50);
  const state = await applyProgressionEvent(initialProgressionState(), {
    id: 'e1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1, vdfIterations: 50, vdfOutput: otherOutput },
  });
  assert.equal(state.domains.d, undefined);
});

test('independent domains advance independently', async () => {
  let state = initialProgressionState();
  const pa = await progressionPayload('a', 1);
  const pb = await progressionPayload('b', 1);
  state = await applyProgressionEvent(state, { id: 'ea', parents: [], payload: pa });
  state = await applyProgressionEvent(state, { id: 'eb', parents: [], payload: pb });
  assert.equal(state.domains.a.epoch, 1);
  assert.equal(state.domains.b.epoch, 1);
});

test('invalid domain and epoch shapes are rejected without throwing', async () => {
  let state = initialProgressionState();
  state = await applyProgressionEvent(state, { id: 'e1', parents: [], payload: { type: 'progression', domain: '', epoch: 1 } });
  state = await applyProgressionEvent(state, { id: 'e2', parents: [], payload: { type: 'progression', domain: 'd', epoch: 0 } });
  state = await applyProgressionEvent(state, { id: 'e3', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1.5 } });
  assert.equal(Object.keys(state.domains).length, 0);
});

test('non-progression events pass through unchanged', async () => {
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload: { type: 'other' } });
  assert.deepEqual(state, initialProgressionState());
});

test('a real, honestly-computed sequence of several epochs is accepted end to end', async () => {
  let state = initialProgressionState();
  let lastId = null;
  let previousOutput = 'genesis';
  for (let e = 1; e <= 4; e++) {
    const payload = await progressionPayload('d', e, previousOutput);
    const id = `e${e}`;
    state = await applyProgressionEvent(state, { id, parents: lastId ? [lastId] : [], payload });
    lastId = id;
    previousOutput = payload.vdfOutput;
  }
  assert.equal(state.domains.d.epoch, 4);
  assert.equal(state.rejections.length, 0);
});

test('materializeProgression folds a real sequence via a real reducer-shaped event list', async () => {
  const p1 = await progressionPayload('d', 1);
  const p2 = await progressionPayload('d', 2, p1.vdfOutput);
  const events = [
    { id: 'e1', parents: [], payload: p1 },
    { id: 'e2', parents: ['e1'], payload: p2 },
  ];
  const state = await materializeProgression(events);
  assert.equal(state.domains.d.epoch, 2);
});

test('THE REAL INJECTION: a custom verifyFn is genuinely used instead of the default, real recomputation', async () => {
  let realVerifyCalls = 0;
  const spy = async (seed, iterations, output) => {
    realVerifyCalls += 1;
    return await verifyVdfChain(seed, iterations, output);
  };
  const payload = await progressionPayload('d', 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload }, spy);
  assert.equal(realVerifyCalls, 1, 'the injected function must be the one actually invoked');
  assert.equal(state.domains.d.epoch, 1);
});

test('SECURITY: an injected verifyFn that always returns false rejects even a real, honestly-computed proof — the caller stays in full control', async () => {
  const alwaysFalse = async () => false;
  const payload = await progressionPayload('d', 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload }, alwaysFalse);
  assert.equal(state.domains.d, undefined);
  assert.equal(state.rejections.length, 1);
});

test('materializeProgression also accepts and genuinely uses a custom verifyFn', async () => {
  let calls = 0;
  const spy = async (seed, iterations, output) => { calls += 1; return await verifyVdfChain(seed, iterations, output); };
  const p1 = await progressionPayload('d', 1);
  const p2 = await progressionPayload('d', 2, p1.vdfOutput);
  const events = [{ id: 'e1', parents: [], payload: p1 }, { id: 'e2', parents: ['e1'], payload: p2 }];
  const state = await materializeProgression(events, spy);
  assert.equal(calls, 2);
  assert.equal(state.domains.d.epoch, 2);
});

test('SECURITY, THE REAL REGRESSION FOUND AND CLOSED: an explicit null verifyFn (never the same as omitting the argument) falls back to real, full VDF verification, instead of crashing', async () => {
  const p1 = await progressionPayload('d', 1);
  const events = [{ id: 'e1', parents: [], payload: p1 }];
  const state = await applyProgressionEvent(initialProgressionState(), events[0], null);
  assert.equal(state.domains.d.epoch, 1, 'a real, valid progression event must still be accepted with an explicit null verifyFn, never crash');
  assert.equal(state.rejections.length, 0);
});

test('SECURITY: with an explicit null verifyFn, a real, invalid VDF proof is still genuinely rejected — the fallback is real verification, never a silent bypass', async () => {
  const fake = { type: 'progression', domain: 'd', epoch: 1, vdfIterations: 30, vdfOutput: 'fabricated-never-computed' };
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload: fake }, null);
  assert.equal(state.rejections.length, 1);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});
