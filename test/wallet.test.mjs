import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import { claimableNow } from '../src/accrual.js';
import {
  initialWalletState, applyWalletEvent, materializeWallet,
  buildSignedTransferEvent, buildSignedSplitEvent, spendableClaims, totalBalance,
  issueDelegation, buildSignedDelegatedTransferEvent, buildSignedDelegatedSplitEvent,
  deriveVoucherAddress, buildSignedVoucherRedeemEvent, buildSignedDelegatedVoucherRedeemEvent,
} from '../src/wallet.js';
import { buildSignedAccrualEvent, buildSignedClaimEvent, buildSignedDelegatedClaimEvent } from '../src/accrual.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { toUnits, fromUnits } from '../src/units.js';

const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}

async function advanceEpochs(state, signer, count) {
  const domain = await deriveId(signer.pubkeyBytes);
  const current = state.accrual.progression.domains[domain] ?? { epoch: 0, vdfOutput: null, lastId: null };
  let epoch = current.epoch;
  let previousOutput = current.vdfOutput ?? 'genesis';
  let lastId = current.lastId;
  for (let i = 0; i < count; i++) {
    epoch += 1;
    const seed = vdfSeed(domain, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `${domain}-p${epoch}-${crypto.randomUUID()}`;
    const signedProgression = await buildSignedProgressionEvent({ domain, epoch, vdfIterations: 50, vdfOutput }, signer.seed, signer.pubkeyBytes);
    state = await applyWalletEvent(rewardParams, state, { id, parents: lastId ? [lastId] : [], payload: { type: 'progression', ...signedProgression } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  return state;
}

async function readyToClaimDomain(signer, epochs = 5, b = 10) {
  const domain = await deriveId(signer.pubkeyBytes);
  let state = await advanceEpochs(initialWalletState(), signer, epochs);
  const accrualId = crypto.randomUUID();
  const signedAccrual = await buildSignedAccrualEvent({ domain, b }, signer.seed, signer.pubkeyBytes);
  state = await applyWalletEvent(rewardParams, state, { id: accrualId, parents: [], payload: { type: 'accrual', ...signedAccrual } });
  state = await advanceEpochs(state, signer, epochs);
  return { state, lastId: accrualId };
}

test('a claim event debits the accrued position and creates a matching Conservation claim', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const { state } = await readyToClaimDomain(alice);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  assert.ok(claimable > 0n);
  const claimAmount = fromUnits(claimable);
  const signedClaim = await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...signedClaim } });
  assert.equal(after.conservation.claims.claim1.amount, toUnits(claimAmount));
  assert.equal(after.conservation.claims.claim1.owner, aliceId);
  assert.equal(after.accrual.balances[aliceId], toUnits(claimAmount));
});

test('SECURITY: a claim larger than what is currently claimable touches neither accrual nor conservation', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const { state } = await readyToClaimDomain(alice);
  const signedClaim = await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: '999999999' }, alice.seed, alice.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...signedClaim } });
  assert.equal(after.accrual.balances[aliceId] ?? 0n, 0n);
  assert.equal(after.conservation.claims.claim1, undefined);
});

test('SECURITY: a duplicate claimId is rejected before either side is touched', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const { state } = await readyToClaimDomain(alice);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimable / 2n);
  const signedClaim = await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes);
  let after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...signedClaim } });
  const balanceAfterFirst = after.accrual.balances[aliceId];
  after = await applyWalletEvent(rewardParams, after, { id: 'c2', parents: ['c1'], payload: { type: 'claim', ...signedClaim } });
  assert.equal(after.accrual.balances[aliceId], balanceAfterFirst);
});

test('a real signed transfer moves ownership between real identities', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const bobId = 'bob-domain-id';

  const { state } = await readyToClaimDomain(alice);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimable);
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes)) } });

  const transferEvent = await buildSignedTransferEvent({ claimId: 'claim1', from: aliceId, to: bobId }, alice.seed, alice.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'transfer', ...transferEvent } });

  const bobClaims = spendableClaims(s, bobId);
  assert.equal(bobClaims.length, 1);
  assert.equal(bobClaims[0].amount, toUnits(claimAmount));
});

test('SECURITY: a forged transfer is rejected', async () => {
  const alice = makeSigner();
  const attacker = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);

  const { state } = await readyToClaimDomain(alice);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimable);
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes)) } });

  const forged = await buildSignedTransferEvent({ claimId: 'claim1', from: aliceId, to: 'attacker-domain' }, attacker.seed, attacker.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'transfer', ...forged } });

  assert.equal(s.conservation.claims.claim1.owner, aliceId);
  assert.equal(s.conservation.claims.claim1.status, 'active');
});

test('a replayed transfer nonce is rejected', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);

  const { state } = await readyToClaimDomain(alice);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, aliceId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes)) } });

  const event1 = await buildSignedTransferEvent({ claimId: 'claim1', from: aliceId, to: 'bob' }, alice.seed, alice.pubkeyBytes, { nonce: 'fixed' });
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'transfer', ...event1 } });
  s = await applyWalletEvent(rewardParams, s, { id: 't2', parents: ['t1'], payload: { type: 'transfer', ...event1 } });

  assert.equal(spendableClaims(s, 'bob').length, 1);
});

test('a real signed split divides a real claim, both amounts real bigint', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);

  const { state } = await readyToClaimDomain(alice);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, aliceId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes)) } });

  const totalUnits = toUnits(claimAmount);
  const firstAmount = fromUnits(totalUnits / 2n);
  const splitEvent = await buildSignedSplitEvent({ claimId: 'claim1', owner: aliceId, firstAmount, firstId: 'c1a', secondId: 'c1b' }, alice.seed, alice.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 's1', parents: ['c1'], payload: { type: 'split', ...splitEvent } });

  assert.equal(s.conservation.claims.c1a.amount + s.conservation.claims.c1b.amount, totalUnits);
});

test('totalBalance sums unclaimed-but-growing plus already-claimed, with no double count once a claim exists', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const { state } = await readyToClaimDomain(alice);
  const claimableBefore = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimableBefore);
  const signedClaim = await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, alice.seed, alice.pubkeyBytes);
  const s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...signedClaim } });
  const total = totalBalance(rewardParams, s, aliceId);
  assert.ok(total >= toUnits(claimAmount), 'must be at least what was claimed');
  assert.ok(total < toUnits(claimAmount) * 2n, 'must never double-count the same already-claimed value');
});

test('materializeWallet folds a real, complete sequence end to end', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const events = [];
  let previousOutput = 'genesis';
  let lastId = null;
  for (let e = 1; e <= 3; e++) {
    const seed = vdfSeed(aliceId, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `p${e}`;
    const signedProgression = await buildSignedProgressionEvent({ domain: aliceId, epoch: e, vdfIterations: 50, vdfOutput }, alice.seed, alice.pubkeyBytes);
    events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', ...signedProgression } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  const signedAccrual = await buildSignedAccrualEvent({ domain: aliceId, b: 10 }, alice.seed, alice.pubkeyBytes);
  events.push({ id: 'a1', parents: [lastId], payload: { type: 'accrual', ...signedAccrual } });
  const state = await materializeWallet(rewardParams, events);
  assert.equal(state.accrual.progression.domains[aliceId].epoch, 3);
  assert.equal(state.accrual.positions[aliceId].b, 10);
});

test('THE REAL INCREMENTAL CATCH-UP PROPERTY: applying only newly-arrived events on top of already-materialized state produces byte-identical results to a full replay from scratch', async () => {
  const events = [];

  // Two real, causally-independent domains — the real scenario a
  // real P2P sync or file import would bring in together.
  for (const signer of [makeSigner(), makeSigner()]) {
    const domain = await deriveId(signer.pubkeyBytes);
    let previousOutput = 'genesis';
    let lastId = null;
    for (let e = 1; e <= 3; e++) {
      const seed = vdfSeed(domain, previousOutput);
      const vdfOutput = await computeVdfChain(seed, 30);
      const id = `${domain}-e${e}`;
      const signedProgression = await buildSignedProgressionEvent({ domain, epoch: e, vdfIterations: 30, vdfOutput }, signer.seed, signer.pubkeyBytes);
      events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', ...signedProgression } });
      lastId = id;
      previousOutput = vdfOutput;
    }
  }

  const fullReplay = await materializeWallet(rewardParams, events, null, null, {});

  // Real, incremental catch-up: half the events already "covered",
  // matching what a real, partial materialization looks like.
  const coveredIds = new Set(events.slice(0, 3).map((e) => e.id));
  let incremental = await materializeWallet(rewardParams, events.filter((e) => coveredIds.has(e.id)), null, null, {});
  for (const event of events.filter((e) => !coveredIds.has(e.id))) {
    incremental = await applyWalletEvent(rewardParams, incremental, event, null, {});
  }

  assert.deepEqual(fullReplay, incremental, 'a real, partial-then-incremental catch-up must produce an identical real wallet state to a full replay — the exact property an incremental sync relies on to avoid O(total history) cost on every real sync');
});

test('"sign once, click many times": a real delegation lets a delegate key move an owner\'s claim repeatedly, without the owner\'s own key signing again', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  // The one, real signature the owner's own root key ever produces for this whole channel.
  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  assert.equal(delegation.from, ownerId);

  // Every subsequent "click" reuses the SAME delegation, signed fresh each time by the delegate alone.
  const send1 = await buildSignedDelegatedTransferEvent(delegation, { claimId: 'claim1', to: 'bob' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'delegated-transfer', ...send1 } });

  assert.equal(spendableClaims(s, 'bob').length, 1);
  assert.equal(spendableClaims(s, 'bob')[0].amount, toUnits(claimAmount));
  assert.equal(s.conservation.claims.claim1.status, 'consumed');
});

test('SECURITY: a delegated transfer with no real delegation ever issued is rejected', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  // The delegate signs everything themselves — a real delegation, but
  // issued by their OWN key, never the real owner's — then forges the
  // `from` field afterward to claim it was really the owner.
  const fakeDelegation = { ...(await issueDelegation(delegateKey.seed, delegateKey.pubkeyBytes, delegateKey.pubkeyBytes)), from: ownerId };
  const forged = await buildSignedDelegatedTransferEvent(fakeDelegation, { claimId: 'claim1', to: 'attacker' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'delegated-transfer', ...forged } });

  assert.equal(s.conservation.claims.claim1.owner, ownerId);
  assert.equal(s.conservation.claims.claim1.status, 'active');
});

test('SECURITY: a real delegation for a DIFFERENT delegate key cannot be reused by an unauthorized key', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const realDelegate = makeSigner();
  const impostor = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, realDelegate.pubkeyBytes); // authorizes realDelegate specifically
  const impostorAttempt = await buildSignedDelegatedTransferEvent(delegation, { claimId: 'claim1', to: 'attacker' }, impostor.seed, impostor.pubkeyBytes); // but impostor signs instead
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'delegated-transfer', ...impostorAttempt } });

  assert.equal(s.conservation.claims.claim1.status, 'active', 'a delegation for one real key must never authorize a different one');
});

test('SECURITY: a replayed delegated-transfer nonce is rejected, exactly like an ordinary transfer', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const event1 = await buildSignedDelegatedTransferEvent(delegation, { claimId: 'claim1', to: 'bob' }, delegateKey.seed, delegateKey.pubkeyBytes, { nonce: 'fixed' });
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'delegated-transfer', ...event1 } });
  s = await applyWalletEvent(rewardParams, s, { id: 't2', parents: ['t1'], payload: { type: 'delegated-transfer', ...event1 } });

  assert.equal(spendableClaims(s, 'bob').length, 1, 'the replayed event must never move a second, already-consumed claim again');
});

test('a real delegate can click many times in a row, each a fresh, independent real transfer, reusing the identical one-time delegation', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();
  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);

  const { state } = await readyToClaimDomain(owner, 5, 30);
  const claimable = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimable }, owner.seed, owner.pubkeyBytes)) } });

  // The SAME delegation also authorizes splitting — the owner's root
  // key never signs again after issueDelegation, not even for this.
  const splitOne = await buildSignedDelegatedSplitEvent(delegation, { claimId: 'claim1', firstAmount: (Number(claimable) / 3).toString(), firstId: 'c1a', secondId: 'c1b' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split1', parents: ['c1'], payload: { type: 'delegated-split', ...splitOne } });
  const splitTwo = await buildSignedDelegatedSplitEvent(delegation, { claimId: 'c1b', firstAmount: (Number(claimable) / 3).toString(), firstId: 'c1c', secondId: 'c1d' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split2', parents: ['split1'], payload: { type: 'delegated-split', ...splitTwo } });

  for (const claimId of ['c1a', 'c1c', 'c1d']) {
    const send = await buildSignedDelegatedTransferEvent(delegation, { claimId, to: 'bob' }, delegateKey.seed, delegateKey.pubkeyBytes);
    s = await applyWalletEvent(rewardParams, s, { id: `send-${claimId}`, parents: [`split2`], payload: { type: 'delegated-transfer', ...send } });
  }

  assert.equal(spendableClaims(s, 'bob').length, 3, 'three real, independent clicks, each its own real transfer — the owner\'s root key signed exactly once, for the delegation, at the very start');
});

test('"sign once, click forever": a delegated split needs no exact-amount claim, and never touches the owner\'s key again', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const half = (Number(claimAmount) / 2).toString();
  const split = await buildSignedDelegatedSplitEvent(delegation, { claimId: 'claim1', firstAmount: half, firstId: 'half1', secondId: 'half2' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split1', parents: ['c1'], payload: { type: 'delegated-split', ...split } });

  const send = await buildSignedDelegatedTransferEvent(delegation, { claimId: 'half1', to: 'bob' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['split1'], payload: { type: 'delegated-transfer', ...send } });

  assert.equal(spendableClaims(s, 'bob').length, 1);
  assert.equal(spendableClaims(s, 'bob')[0].amount, toUnits(half));
  assert.equal(s.conservation.claims.half2.owner, ownerId, 'the leftover half stays with the real owner');
});

test('SECURITY: a delegated split with no real delegation ever issued is rejected', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  const fakeDelegation = { ...(await issueDelegation(delegateKey.seed, delegateKey.pubkeyBytes, delegateKey.pubkeyBytes)), from: ownerId };
  const forged = await buildSignedDelegatedSplitEvent(fakeDelegation, { claimId: 'claim1', firstAmount: (Number(claimAmount) / 2).toString(), firstId: 'half1', secondId: 'half2' }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split1', parents: ['c1'], payload: { type: 'delegated-split', ...forged } });

  assert.equal(s.conservation.claims.claim1.status, 'active', 'a forged delegation must never authorize splitting the real owner\'s claim');
});

test('SECURITY: a replayed delegated-split nonce is rejected', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: ownerId, claimId: 'claim1', amount: claimAmount }, owner.seed, owner.pubkeyBytes)) } });

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const split = await buildSignedDelegatedSplitEvent(delegation, { claimId: 'claim1', firstAmount: (Number(claimAmount) / 2).toString(), firstId: 'half1', secondId: 'half2' }, delegateKey.seed, delegateKey.pubkeyBytes, { nonce: 'fixed' });
  let once = await applyWalletEvent(rewardParams, s, { id: 'split1', parents: ['c1'], payload: { type: 'delegated-split', ...split } });
  let twice = await applyWalletEvent(rewardParams, once, { id: 'split2', parents: ['split1'], payload: { type: 'delegated-split', ...split } });

  assert.equal(once.conservation.claims.half1.status, 'active', 'the first, real split applied');
  assert.deepEqual(once.conservation, twice.conservation, 'the replayed split must never run a second time');
});

test('a real bearer voucher: issue by hash-lock, redeem by revealing the secret — "the QR can be copied, but only the first redemption succeeds"', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const redeemer = makeSigner();
  const redeemerId = await deriveId(redeemer.pubkeyBytes);

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'a real, random secret — this is what goes in the QR code';
  const voucherAddress = await deriveVoucherAddress(secret);

  // Issuing needs NO new protocol: an ordinary, already-existing signed
  // transfer, just addressed to the hash of a secret instead of a real identity.
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  assert.equal(spendableClaims(s, voucherAddress).length, 1, 'the value is real and owned by the voucher address — nobody\'s root key can sign for it');

  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;
  const redeem = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret, to: redeemerId }, redeemer.seed, redeemer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'voucher-redeem', ...redeem } });

  assert.equal(spendableClaims(s, redeemerId).length, 1);
  assert.equal(spendableClaims(s, redeemerId)[0].amount, toUnits(claimAmount));
  assert.equal(spendableClaims(s, voucherAddress).length, 0, 'the voucher is spent — nothing left to redeem again');
});

test('SECURITY: redeeming with the wrong secret has no real effect', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const attacker = makeSigner();
  const attackerId = await deriveId(attacker.pubkeyBytes);

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const voucherAddress = await deriveVoucherAddress('the real secret');
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  const guess = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret: 'a guessed, wrong secret', to: attackerId }, attacker.seed, attacker.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'voucher-redeem', ...guess } });

  assert.equal(spendableClaims(s, attackerId).length, 0, 'a wrong secret must never redeem real value');
  assert.equal(spendableClaims(s, voucherAddress).length, 1, 'the voucher is untouched, still redeemable by whoever really knows the secret');
});

test('SECURITY: the real "only once" property — two real redeemers racing for the same secret, only the first applied wins', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const bob = makeSigner();
  const bobId = await deriveId(bob.pubkeyBytes);

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'shown once, in one QR code';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  // Both scanned the identical QR — both real, both signed by a real,
  // distinct key, both genuinely knowing the real secret.
  const aliceRedeem = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret, to: aliceId }, alice.seed, alice.pubkeyBytes);
  const bobRedeem = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret, to: bobId }, bob.seed, bob.pubkeyBytes);

  s = await applyWalletEvent(rewardParams, s, { id: 'redeem-alice', parents: ['issue'], payload: { type: 'voucher-redeem', ...aliceRedeem } });
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem-bob', parents: ['redeem-alice'], payload: { type: 'voucher-redeem', ...bobRedeem } });

  assert.equal(spendableClaims(s, aliceId).length, 1, 'alice\'s redemption was applied first — she really gets it');
  assert.equal(spendableClaims(s, bobId).length, 0, 'bob\'s later redemption of the identical, already-consumed voucher has no real effect');
});

test('SECURITY: a redeemer cannot claim a voucher into an identity they do not really control', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const attacker = makeSigner();
  const victim = makeSigner();
  const victimId = await deriveId(victim.pubkeyBytes);

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'a real secret the attacker genuinely knows';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  // Attacker really knows the secret, but signs with their OWN key
  // while claiming `to: victimId` — trying to redirect the redemption
  // to a victim's id they don't control (e.g. to frame them, or by a
  // naive client bug). The signer must really derive the claimed `to`.
  const forged = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret, to: victimId }, attacker.seed, attacker.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'voucher-redeem', ...forged } });

  assert.equal(spendableClaims(s, victimId).length, 0);
  assert.equal(spendableClaims(s, voucherAddress).length, 1, 'a redemption with a forged `to` has no real effect — the voucher stays redeemable');
});

test('SECURITY: a replayed voucher-redeem nonce is rejected', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const redeemer = makeSigner();
  const redeemerId = await deriveId(redeemer.pubkeyBytes);

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'replay test secret';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  const redeem = await buildSignedVoucherRedeemEvent({ claimId: voucherClaimId, secret, to: redeemerId }, redeemer.seed, redeemer.pubkeyBytes, { nonce: 'fixed' });
  let once = await applyWalletEvent(rewardParams, s, { id: 'redeem1', parents: ['issue'], payload: { type: 'voucher-redeem', ...redeem } });
  let twice = await applyWalletEvent(rewardParams, once, { id: 'redeem2', parents: ['redeem1'], payload: { type: 'voucher-redeem', ...redeem } });

  assert.deepEqual(once.conservation, twice.conservation, 'the replayed identical event must never run a second time');
});

test('a real delegate can redeem a voucher landing the value in the real owner\'s identity, never the delegate\'s own', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'a real secret, redeemable through a channel';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const redeem = await buildSignedDelegatedVoucherRedeemEvent(delegation, { claimId: voucherClaimId, secret }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'delegated-voucher-redeem', ...redeem } });

  assert.equal(spendableClaims(s, ownerId).length, 1, 'the real owner receives it — never the delegate\'s own session identity');
  assert.equal(spendableClaims(s, ownerId)[0].amount, toUnits(claimAmount));
  assert.equal(spendableClaims(s, await deriveId(delegateKey.pubkeyBytes)).length, 0, 'the delegate never actually owns the redeemed value');
});

test('SECURITY: a delegated voucher redemption with no real delegation ever issued is rejected', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'a secret the forger genuinely knows';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  // A fabricated "delegation" the real owner never actually signed —
  // the delegate key itself signs its own fake delegation, then
  // relabels `from` as the real owner's id.
  const fakeDelegation = { ...(await issueDelegation(delegateKey.seed, delegateKey.pubkeyBytes, delegateKey.pubkeyBytes)), from: ownerId };
  const forged = await buildSignedDelegatedVoucherRedeemEvent(fakeDelegation, { claimId: voucherClaimId, secret }, delegateKey.seed, delegateKey.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'delegated-voucher-redeem', ...forged } });

  assert.equal(spendableClaims(s, ownerId).length, 0, 'a real owner who never issued a real delegation must never be credited');
  assert.equal(spendableClaims(s, voucherAddress).length, 1, 'the voucher stays untouched, still redeemable by whoever really knows the secret');
});

test('SECURITY: a real delegation for a DIFFERENT delegate key cannot redeem a voucher', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const realDelegate = makeSigner();
  const impostor = makeSigner();

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'a secret the impostor also happens to know';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, realDelegate.pubkeyBytes); // authorizes realDelegate specifically
  const impostorAttempt = await buildSignedDelegatedVoucherRedeemEvent(delegation, { claimId: voucherClaimId, secret }, impostor.seed, impostor.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'redeem', parents: ['issue'], payload: { type: 'delegated-voucher-redeem', ...impostorAttempt } });

  assert.equal(spendableClaims(s, ownerId).length, 0, 'a delegation for one specific key must never authorize a different one');
  assert.equal(spendableClaims(s, voucherAddress).length, 1);
});

test('SECURITY: a replayed delegated-voucher-redeem nonce is rejected', async () => {
  const issuer = makeSigner();
  const issuerId = await deriveId(issuer.pubkeyBytes);
  const owner = makeSigner();
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(issuer);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, issuerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: issuerId, claimId: 'claim1', amount: claimAmount }, issuer.seed, issuer.pubkeyBytes)) } });

  const secret = 'delegated replay test secret';
  const voucherAddress = await deriveVoucherAddress(secret);
  const issueTransfer = await buildSignedTransferEvent({ claimId: 'claim1', from: issuerId, to: voucherAddress }, issuer.seed, issuer.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'issue', parents: ['c1'], payload: { type: 'transfer', ...issueTransfer } });
  const voucherClaimId = spendableClaims(s, voucherAddress)[0].id;

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const redeem = await buildSignedDelegatedVoucherRedeemEvent(delegation, { claimId: voucherClaimId, secret }, delegateKey.seed, delegateKey.pubkeyBytes, { nonce: 'fixed' });
  let once = await applyWalletEvent(rewardParams, s, { id: 'redeem1', parents: ['issue'], payload: { type: 'delegated-voucher-redeem', ...redeem } });
  let twice = await applyWalletEvent(rewardParams, once, { id: 'redeem2', parents: ['redeem1'], payload: { type: 'delegated-voucher-redeem', ...redeem } });

  assert.deepEqual(once.conservation, twice.conservation, 'the replayed identical event must never run a second time');
});

test('SECURITY: a claim event forged by anyone other than the domain itself creates no Conservation claim — the real, narrow griefing vector the signature check closes', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const attacker = makeSigner();

  const { state } = await readyToClaimDomain(alice);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  assert.ok(claimable > 0n);
  const claimAmount = fromUnits(claimable);

  // Before this check existed, a completely unrelated identity could
  // sign and submit a real 'claim' event naming a domain they have no
  // relationship to, and it was honored as if the real owner had
  // submitted it — not a theft (the resulting claim's owner is still
  // the named domain, spendable only by its real key), but it let
  // anyone reset that domain's own patience clock without consent.
  const forged = await buildSignedClaimEvent({ domain: aliceId, claimId: 'claim1', amount: claimAmount }, attacker.seed, attacker.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', ...forged } });

  assert.equal(after.conservation.claims.claim1, undefined, 'a claim forged by a non-owner must never create a real Conservation claim');
  assert.equal(after.accrual.balances[aliceId] ?? 0n, 0n, 'the real owner\'s balance must be untouched');
  assert.deepEqual(after.accrual.positions[aliceId], state.accrual.positions[aliceId], 'the real owner\'s patience clock must be untouched by a claim they never signed');
});

test('SECURITY: an accrual event forged by anyone other than the domain itself is rejected', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const attacker = makeSigner();

  const forged = await buildSignedAccrualEvent({ domain: aliceId, b: 1000 }, attacker.seed, attacker.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, initialWalletState(), { id: 'a1', parents: [], payload: { type: 'accrual', ...forged } });

  assert.equal(after.accrual.positions[aliceId], undefined, 'a real signature from anyone other than the domain itself must never commit capital on its behalf');
});

test('a real delegate can trigger a claim landing the value under the real owner\'s domain, never the delegate\'s own', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const delegatedClaim = await buildSignedDelegatedClaimEvent(delegation, { claimId: 'claim1', amount: claimAmount }, delegateKey.seed, delegateKey.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'delegated-claim', ...delegatedClaim } });

  assert.equal(after.conservation.claims.claim1.owner, ownerId, 'the real owner receives the claim — never the delegate\'s own session identity');
  assert.equal(after.conservation.claims.claim1.amount, toUnits(claimAmount));
  assert.equal(after.accrual.balances[ownerId], toUnits(claimAmount));
});

test('SECURITY: a delegated claim with no real delegation ever issued creates no Conservation claim', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));

  const fakeDelegation = { ...(await issueDelegation(delegateKey.seed, delegateKey.pubkeyBytes, delegateKey.pubkeyBytes)), from: ownerId };
  const forged = await buildSignedDelegatedClaimEvent(fakeDelegation, { claimId: 'claim1', amount: claimAmount }, delegateKey.seed, delegateKey.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'delegated-claim', ...forged } });

  assert.equal(after.conservation.claims.claim1, undefined, 'a forged delegation must never authorize claiming on the real owner\'s behalf');
  assert.equal(after.accrual.balances[ownerId] ?? 0n, 0n);
});

test('SECURITY: a real delegation for a DIFFERENT delegate key cannot trigger a claim', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const realDelegate = makeSigner();
  const impostor = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, realDelegate.pubkeyBytes);
  const impostorAttempt = await buildSignedDelegatedClaimEvent(delegation, { claimId: 'claim1', amount: claimAmount }, impostor.seed, impostor.pubkeyBytes);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'delegated-claim', ...impostorAttempt } });

  assert.equal(after.conservation.claims.claim1, undefined, 'a delegation for one specific key must never authorize a different one');
});

test('SECURITY: a replayed delegated-claim nonce is rejected', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(owner);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId) / 2n);

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, delegateKey.pubkeyBytes);
  const delegatedClaim = await buildSignedDelegatedClaimEvent(delegation, { claimId: 'claim1', amount: claimAmount }, delegateKey.seed, delegateKey.pubkeyBytes, { nonce: 'fixed' });
  let once = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'delegated-claim', ...delegatedClaim } });
  let twice = await applyWalletEvent(rewardParams, once, { id: 'c2', parents: ['c1'], payload: { type: 'delegated-claim', ...delegatedClaim } });

  assert.deepEqual(once.accrual.balances, twice.accrual.balances, 'the replayed identical delegated claim must never debit the balance a second time');
});
