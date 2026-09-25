import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import {
  initialAccrualState, applyAccrualEvent, materializeAccrual, claimableNow,
  buildSignedAccrualEvent, buildSignedClaimEvent,
} from '../src/accrual.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { fromUnits } from '../src/units.js';

const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}

// A shared, real signer for the domain nearly every test below commits
// capital to and claims from — signing is required (see accrual.js's
// own header) but doesn't need to vary per test, since each test starts
// from its own fresh initialAccrualState().
const domainSigner = makeSigner();
const domain = await deriveId(domainSigner.pubkeyBytes);

async function accrue(state, b, { id, parents = [], T } = {}) {
  const signed = await buildSignedAccrualEvent({ domain, b, T }, domainSigner.seed, domainSigner.pubkeyBytes);
  return applyAccrualEvent(rewardParams, state, { id, parents, payload: { type: 'accrual', ...signed } });
}

async function claim(state, amount, { id, parents = [] } = {}) {
  const signed = await buildSignedClaimEvent({ domain, amount, claimId: id }, domainSigner.seed, domainSigner.pubkeyBytes);
  return applyAccrualEvent(rewardParams, state, { id, parents, payload: { type: 'claim', ...signed } });
}

// forDomain is always the shared `domain` above in every real call site
// here, so domainSigner is really the correct — and only — signer able
// to produce a progression event that verifies for it.
async function advanceEpochs(state, forDomain, count) {
  const current = state.progression.domains[forDomain] ?? { epoch: 0, vdfOutput: null, lastId: null };
  let epoch = current.epoch;
  let previousOutput = current.vdfOutput ?? 'genesis';
  let lastId = current.lastId;
  for (let i = 0; i < count; i++) {
    epoch += 1;
    const seed = vdfSeed(forDomain, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `${forDomain}-p${epoch}`;
    const signed = await buildSignedProgressionEvent({ domain: forDomain, epoch, vdfIterations: 50, vdfOutput }, domainSigner.seed, domainSigner.pubkeyBytes);
    const ev = { id, parents: lastId ? [lastId] : [], payload: { type: 'progression', ...signed } };
    state = await applyAccrualEvent(rewardParams, state, ev);
    lastId = id;
    previousOutput = vdfOutput;
  }
  return state;
}

test('an accrual event commits capital but does not itself create spendable balance', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  assert.equal(state.balances[domain] ?? 0n, 0n, 'balance is only ever created by an actual claim');
  assert.equal(state.positions[domain].b, 10);
});

test('a second accrual event adds to the already-committed capital', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await accrue(state, 5, { id: 'a2', parents: ['a1'] });
  assert.equal(state.positions[domain].b, 15);
});

test('THE REAL FIX, VERIFIED ON A SECOND BURN: a later accrual event on an already-matured position resets the patience clock too, not just the first one', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 10);
  state = await accrue(state, 5, { id: 'a1' });
  assert.equal(state.positions[domain].lastActionEpoch, 10);

  state = await advanceEpochs(state, domain, 20);
  const claimableBeforeSecondBurn = claimableNow(rewardParams, state, domain);
  assert.ok(claimableBeforeSecondBurn > 0n, 'the position must have genuinely matured before the second burn');

  state = await accrue(state, 5, { id: 'a2', parents: ['a1'] });
  assert.equal(state.positions[domain].lastActionEpoch, 30, 'must update to the real, current epoch — not stay stuck at the first burn\'s epoch');
  assert.equal(claimableNow(rewardParams, state, domain), 0n, 'claimable must drop back to zero right after the second burn too — t genuinely resets every time, not only once');
});

test('claimableNow reflects real, positive reward once epochs have passed since the position opened', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 5);
  assert.ok(claimableNow(rewardParams, state, domain) > 0n);
});

test('a claim debits real bigint balance up to what is currently claimable', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 5);
  const claimable = claimableNow(rewardParams, state, domain);
  assert.ok(claimable > 0n);
  const claimAmount = fromUnits(claimable / 2n);
  state = await claim(state, claimAmount, { id: 'c1' });
  assert.equal(state.balances[domain], claimable / 2n);
});

test('SECURITY: a claim larger than what is currently claimable is rejected', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await claim(state, '999999999', { id: 'c1' });
  assert.equal(state.balances[domain] ?? 0n, 0n);
  assert.equal(state.rejections.length, 1);
});

test('THE REAL FIX: claiming resets the patience clock — claimableNow drops right after a claim, at the same real epoch', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 10);
  const claimableBefore = claimableNow(rewardParams, state, domain);
  assert.ok(claimableBefore > 0n);

  const claimAmount = fromUnits(claimableBefore);
  state = await claim(state, claimAmount, { id: 'c1' });

  const claimableRightAfter = claimableNow(rewardParams, state, domain);
  assert.ok(claimableRightAfter < claimableBefore, 'the clock must reset — at the identical real epoch, claiming again should yield far less');
});

test('THE REAL FIX, VERIFIED ON A SECOND CLAIM: claiming a second time, well after the first, resets the patience clock again from that real, current epoch — never from the first claim', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 10);
  const firstClaimAmount = fromUnits(claimableNow(rewardParams, state, domain));
  state = await claim(state, firstClaimAmount, { id: 'c1' });
  const epochAfterFirstClaim = state.positions[domain].lastActionEpoch;

  state = await advanceEpochs(state, domain, 15);
  const claimableBeforeSecond = claimableNow(rewardParams, state, domain);
  assert.ok(claimableBeforeSecond > 0n, 'must have genuinely matured again since the first claim');

  const secondClaimAmount = fromUnits(claimableBeforeSecond);
  state = await claim(state, secondClaimAmount, { id: 'c2', parents: ['c1'] });
  assert.notEqual(state.positions[domain].lastActionEpoch, epochAfterFirstClaim, 'must move forward, not stay pinned to the first claim\'s epoch');
  assert.equal(claimableNow(rewardParams, state, domain), 0n, 'claimable must drop back to zero right after the second claim too');
});

test('SECURITY, THE REAL BUG FOUND AND FIXED: no payload field can fabricate an early reference epoch', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 5);
  const signed = await buildSignedAccrualEvent({ domain, b: 10 }, domainSigner.seed, domainSigner.pubkeyBytes);
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', ...signed, q0: -99999 } });
  assert.equal(state.positions[domain].lastActionEpoch, 5, 'lastActionEpoch must be the real, current domain epoch, never a caller-supplied value');
});

test('a claim for a domain with no committed capital is rejected', async () => {
  const ghostSigner = makeSigner();
  const ghostId = await deriveId(ghostSigner.pubkeyBytes);
  const signed = await buildSignedClaimEvent({ domain: ghostId, amount: '5', claimId: 'c1' }, ghostSigner.seed, ghostSigner.pubkeyBytes);
  const state = await applyAccrualEvent(rewardParams, initialAccrualState(), { id: 'c1', parents: [], payload: { type: 'claim', ...signed } });
  assert.equal(state.rejections.length, 1);
});

test('malformed accrual events are rejected without throwing', async () => {
  let state = initialAccrualState();
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', domain: '', b: 10 } });
  state = await applyAccrualEvent(rewardParams, state, { id: 'a2', parents: [], payload: { type: 'accrual', domain, b: -1 } });
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
    const seed = vdfSeed(domain, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `p${e}`;
    const signedProgression = await buildSignedProgressionEvent({ domain, epoch: e, vdfIterations: 50, vdfOutput }, domainSigner.seed, domainSigner.pubkeyBytes);
    events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', ...signedProgression } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  const signed = await buildSignedAccrualEvent({ domain, b: 10 }, domainSigner.seed, domainSigner.pubkeyBytes);
  events.push({ id: 'a1', parents: [lastId], payload: { type: 'accrual', ...signed } });
  const finalState = await materializeAccrual(rewardParams, events);
  assert.equal(finalState.progression.domains[domain].epoch, 5);
  assert.equal(finalState.positions[domain].b, 10);
});

test('SECURITY: an accrual event naming a domain the real signer does not control is rejected', async () => {
  const victim = makeSigner();
  const victimId = await deriveId(victim.pubkeyBytes);
  const attacker = makeSigner();

  // The attacker signs for real, but names the victim's domain instead of their own.
  const forged = await buildSignedAccrualEvent({ domain: victimId, b: 1000 }, attacker.seed, attacker.pubkeyBytes);
  const state = await applyAccrualEvent(rewardParams, initialAccrualState(), { id: 'a1', parents: [], payload: { type: 'accrual', ...forged } });

  assert.equal(state.positions[victimId], undefined, 'a real signature from anyone other than the domain itself must never commit capital on its behalf');
  assert.equal(state.rejections.length, 1);
});

test('SECURITY: a claim event naming a domain the real signer does not control is rejected — this is the real, narrow griefing vector the signature check closes', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 10);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 10);
  const claimableBefore = claimableNow(rewardParams, state, domain);
  assert.ok(claimableBefore > 0n);
  const positionBefore = state.positions[domain];

  // An attacker with no relationship to `domain` signs a real claim
  // naming it anyway — before this check existed, this was honored
  // exactly as if the real owner had submitted it, silently resetting
  // their patience clock without consent.
  const attacker = makeSigner();
  const forged = await buildSignedClaimEvent({ domain, amount: fromUnits(claimableBefore), claimId: 'stolen-claim' }, attacker.seed, attacker.pubkeyBytes);
  state = await applyAccrualEvent(rewardParams, state, { id: 'c-forged', parents: ['a1'], payload: { type: 'claim', ...forged } });

  assert.equal(state.balances[domain] ?? 0n, 0n, 'a forged claim must never move real balance');
  assert.deepEqual(state.positions[domain], positionBefore, 'the real owner\'s patience clock must be untouched by a claim they never signed');
});

test('SECURITY: a replayed accrual nonce is rejected — the identical signed commitment cannot be double-counted', async () => {
  let state = initialAccrualState();
  const signed = await buildSignedAccrualEvent({ domain, b: 10 }, domainSigner.seed, domainSigner.pubkeyBytes, { nonce: 'fixed' });
  state = await applyAccrualEvent(rewardParams, state, { id: 'a1', parents: [], payload: { type: 'accrual', ...signed } });
  state = await applyAccrualEvent(rewardParams, state, { id: 'a2', parents: ['a1'], payload: { type: 'accrual', ...signed } });
  assert.equal(state.positions[domain].b, 10, 'the replayed identical event must never commit capital a second time');
});

test('SECURITY: a replayed claim nonce is rejected — the identical signed claim cannot double-debit the balance', async () => {
  let state = await advanceEpochs(initialAccrualState(), domain, 10);
  state = await accrue(state, 10, { id: 'a1' });
  state = await advanceEpochs(state, domain, 10);
  const claimAmount = fromUnits(claimableNow(rewardParams, state, domain));

  const signed = await buildSignedClaimEvent({ domain, amount: claimAmount, claimId: 'c1' }, domainSigner.seed, domainSigner.pubkeyBytes, { nonce: 'fixed' });
  state = await applyAccrualEvent(rewardParams, state, { id: 'c1', parents: ['a1'], payload: { type: 'claim', ...signed } });
  const balanceAfterFirst = state.balances[domain];
  state = await applyAccrualEvent(rewardParams, state, { id: 'c2', parents: ['c1'], payload: { type: 'claim', ...signed } });
  assert.equal(state.balances[domain], balanceAfterFirst, 'the replayed identical claim must never debit the balance a second time');
});
