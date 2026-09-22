import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { initialAccrualState, applyAccrualEvent, materializeAccrual, claimableNow } from '../src/accrual.js';
import { fromUnits } from '../src/units.js';

const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

async function advanceEpochs(state, domain, count) {
  const current = state.progression.domains[domain] ?? { epoch: 0, vdfOutput: null, lastId: null };
  let epoch = current.epoch;
  let previousOutput = current.vdfOutput ?? 'genesis';
  let lastId = current.lastId;
  for (let i = 0; i < count; i++) {
    epoch += 1;
    const seed = vdfSeed(domain, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `${domain}-p${epoch}`;
    const ev = { id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain, epoch, vdfIterations: 50, vdfOutput } };
    state = await applyAccrualEvent(rewardParams, state, ev);
    lastId = id;
    previousOutput = vdfOutput;
  }
  return state;
}

test('an accrual event commits capital but does not itself create spendable balance', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  assert.equal(state.balances.d ?? 0n, 0n, 'balance is only ever created by an actual claim');
  assert.equal(state.positions.d.b, 10);
});

test('a second accrual event adds to the already-committed capital', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await applyAccrualEvent(rewardParams, state, { id: 'a2', parents: ['a1'], payload: { type: 'accrual', domain: 'd', b: 5 } });
  assert.equal(state.positions.d.b, 15);
});

test('THE REAL FIX, VERIFIED ON A SECOND BURN: a later accrual event on an already-matured position resets the patience clock too, not just the first one', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 10);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 5 } });
  assert.equal(state.positions.d.lastActionEpoch, 10);

  state = await advanceEpochs(state, 'd', 20);
  const claimableBeforeSecondBurn = claimableNow(rewardParams, state, 'd');
  assert.ok(claimableBeforeSecondBurn > 0n, 'the position must have genuinely matured before the second burn');

  state = await applyAccrualEvent(rewardParams, state, { id: 'a2', parents: ['a1'], payload: { type: 'accrual', domain: 'd', b: 5 } });
  assert.equal(state.positions.d.lastActionEpoch, 30, 'must update to the real, current epoch — not stay stuck at the first burn\'s epoch');
  assert.equal(claimableNow(rewardParams, state, 'd'), 0n, 'claimable must drop back to zero right after the second burn too — t genuinely resets every time, not only once');
});

test('claimableNow reflects real, positive reward once epochs have passed since the position opened', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await advanceEpochs(state, 'd', 5);
  assert.ok(claimableNow(rewardParams, state, 'd') > 0n);
});

test('a claim debits real bigint balance up to what is currently claimable', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await advanceEpochs(state, 'd', 5);
  const claimable = claimableNow(rewardParams, state, 'd');
  assert.ok(claimable > 0n);
  const claimAmount = fromUnits(claimable / 2n);
  state = await applyAccrualEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'd', amount: claimAmount } });
  assert.equal(state.balances.d, claimable / 2n);
});

test('SECURITY: a claim larger than what is currently claimable is rejected', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await applyAccrualEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'd', amount: '999999999' } });
  assert.equal(state.balances.d ?? 0n, 0n);
  assert.equal(state.rejections.length, 1);
});

test('THE REAL FIX: claiming resets the patience clock — claimableNow drops right after a claim, at the same real epoch', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await advanceEpochs(state, 'd', 10);
  const claimableBefore = claimableNow(rewardParams, state, 'd');
  assert.ok(claimableBefore > 0n);

  const claimAmount = fromUnits(claimableBefore);
  state = await applyAccrualEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'd', amount: claimAmount } });

  const claimableRightAfter = claimableNow(rewardParams, state, 'd');
  assert.ok(claimableRightAfter < claimableBefore, 'the clock must reset — at the identical real epoch, claiming again should yield far less');
});

test('THE REAL FIX, VERIFIED ON A SECOND CLAIM: claiming a second time, well after the first, resets the patience clock again from that real, current epoch — never from the first claim', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10 } });
  state = await advanceEpochs(state, 'd', 10);
  const firstClaimAmount = fromUnits(claimableNow(rewardParams, state, 'd'));
  state = await applyAccrualEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'd', amount: firstClaimAmount } });
  const epochAfterFirstClaim = state.positions.d.lastActionEpoch;

  state = await advanceEpochs(state, 'd', 15);
  const claimableBeforeSecond = claimableNow(rewardParams, state, 'd');
  assert.ok(claimableBeforeSecond > 0n, 'must have genuinely matured again since the first claim');

  const secondClaimAmount = fromUnits(claimableBeforeSecond);
  state = await applyAccrualEvent(rewardParams, state, { id: 'c2', parents: ['c1'], payload: { type: 'claim', domain: 'd', amount: secondClaimAmount } });
  assert.notEqual(state.positions.d.lastActionEpoch, epochAfterFirstClaim, 'must move forward, not stay pinned to the first claim\'s epoch');
  assert.equal(claimableNow(rewardParams, state, 'd'), 0n, 'claimable must drop back to zero right after the second claim too');
});

test('SECURITY, THE REAL BUG FOUND AND FIXED: no payload field can fabricate an early reference epoch', async () => {
  let state = await advanceEpochs(initialAccrualState(), 'd', 5);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: 'd', b: 10, q0: -99999 } });
  assert.equal(state.positions.d.lastActionEpoch, 5, 'lastActionEpoch must be the real, current domain epoch, never a caller-supplied value');
});

test('a claim for a domain with no committed capital is rejected', async () => {
  const state = await applyAccrualEvent(rewardParams, initialAccrualState(), { id: 'c1', parents: [], payload: { type: 'claim', domain: 'ghost', amount: '5' } });
  assert.equal(state.rejections.length, 1);
});

test('malformed accrual events are rejected without throwing', async () => {
  let state = initialAccrualState();
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: '', b: 10 } });
  state = await applyAccrualEvent(rewardParams, state, { id: 'a2', parents: [], payload: { type: 'accrual', domain: 'd', b: -1 } });
  assert.equal(Object.keys(state.positions).length, 0);
});

test('genesis and other non-economic events pass through unchanged', async () => {
  const state = await applyAccrualEvent(rewardParams, initialAccrualState(), { id: 'g', parents: [], payload: { type: 'genesis' } });
  assert.deepEqual(state, initialAccrualState());
});

test('materializeAccrual folds a real sequence end to end', async () => {
  const events = [];
  let previousOutput = 'genesis';
  let lastId = null;
  for (let e = 1; e <= 5; e++) {
    const seed = vdfSeed('d', previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `p${e}`;
    events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain: 'd', epoch: e, vdfIterations: 50, vdfOutput } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  events.push({ id: 'a1', parents: [lastId], payload: { type: 'accrual', domain: 'd', b: 10 } });
  const finalState = await materializeAccrual(rewardParams, events);
  assert.equal(finalState.progression.domains.d.epoch, 5);
  assert.equal(finalState.positions.d.b, 10);
});
