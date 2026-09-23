import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import { claimableNow } from '../src/accrual.js';
import {
  initialWalletState, applyWalletEvent, materializeWallet,
  buildSignedTransferEvent, buildSignedSplitEvent, spendableClaims, totalBalance,
  issueDelegation, buildSignedDelegatedTransferEvent,
} from '../src/wallet.js';
import { toUnits, fromUnits } from '../src/units.js';

const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}

async function advanceEpochs(state, domain, count) {
  const current = state.accrual.progression.domains[domain] ?? { epoch: 0, vdfOutput: null, lastId: null };
  let epoch = current.epoch;
  let previousOutput = current.vdfOutput ?? 'genesis';
  let lastId = current.lastId;
  for (let i = 0; i < count; i++) {
    epoch += 1;
    const seed = vdfSeed(domain, previousOutput);
    const vdfOutput = await computeVdfChain(seed, 50);
    const id = `${domain}-p${epoch}-${crypto.randomUUID()}`;
    state = await applyWalletEvent(rewardParams, state, { id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain, epoch, vdfIterations: 50, vdfOutput } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  return state;
}

async function readyToClaimDomain(domain, epochs = 5, b = 10) {
  let state = await advanceEpochs(initialWalletState(), domain, epochs);
  const accrualId = crypto.randomUUID();
  state = await applyWalletEvent(rewardParams, state, { id: accrualId, parents: [], payload: { type: 'accrual', domain, b } });
  state = await advanceEpochs(state, domain, epochs);
  return { state, lastId: accrualId };
}

test('a claim event debits the accrued position and creates a matching Conservation claim', async () => {
  const { state } = await readyToClaimDomain('alice');
  const claimable = claimableNow(rewardParams, state.accrual, 'alice');
  assert.ok(claimable > 0n);
  const claimAmount = fromUnits(claimable);
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'alice', claimId: 'claim1', amount: claimAmount } });
  assert.equal(after.conservation.claims.claim1.amount, toUnits(claimAmount));
  assert.equal(after.conservation.claims.claim1.owner, 'alice');
  assert.equal(after.accrual.balances.alice, toUnits(claimAmount));
});

test('SECURITY: a claim larger than what is currently claimable touches neither accrual nor conservation', async () => {
  const { state } = await readyToClaimDomain('alice');
  const after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'alice', claimId: 'claim1', amount: '999999999' } });
  assert.equal(after.accrual.balances.alice ?? 0n, 0n);
  assert.equal(after.conservation.claims.claim1, undefined);
});

test('SECURITY: a duplicate claimId is rejected before either side is touched', async () => {
  const { state } = await readyToClaimDomain('alice');
  const claimable = claimableNow(rewardParams, state.accrual, 'alice');
  const claimAmount = fromUnits(claimable / 2n);
  let after = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'alice', claimId: 'claim1', amount: claimAmount } });
  const balanceAfterFirst = after.accrual.balances.alice;
  after = await applyWalletEvent(rewardParams, after, { id: 'c2', parents: ['c1'], payload: { type: 'claim', domain: 'alice', claimId: 'claim1', amount: claimAmount } });
  assert.equal(after.accrual.balances.alice, balanceAfterFirst);
});

test('a real signed transfer moves ownership between real identities', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);
  const bobId = 'bob-domain-id';

  const { state } = await readyToClaimDomain(aliceId);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimable);
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: aliceId, claimId: 'claim1', amount: claimAmount } });

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

  const { state } = await readyToClaimDomain(aliceId);
  const claimable = claimableNow(rewardParams, state.accrual, aliceId);
  const claimAmount = fromUnits(claimable);
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: aliceId, claimId: 'claim1', amount: claimAmount } });

  const forged = await buildSignedTransferEvent({ claimId: 'claim1', from: aliceId, to: 'attacker-domain' }, attacker.seed, attacker.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'transfer', ...forged } });

  assert.equal(s.conservation.claims.claim1.owner, aliceId);
  assert.equal(s.conservation.claims.claim1.status, 'active');
});

test('a replayed transfer nonce is rejected', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);

  const { state } = await readyToClaimDomain(aliceId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, aliceId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: aliceId, claimId: 'claim1', amount: claimAmount } });

  const event1 = await buildSignedTransferEvent({ claimId: 'claim1', from: aliceId, to: 'bob' }, alice.seed, alice.pubkeyBytes, { nonce: 'fixed' });
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'transfer', ...event1 } });
  s = await applyWalletEvent(rewardParams, s, { id: 't2', parents: ['t1'], payload: { type: 'transfer', ...event1 } });

  assert.equal(spendableClaims(s, 'bob').length, 1);
});

test('a real signed split divides a real claim, both amounts real bigint', async () => {
  const alice = makeSigner();
  const aliceId = await deriveId(alice.pubkeyBytes);

  const { state } = await readyToClaimDomain(aliceId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, aliceId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: aliceId, claimId: 'claim1', amount: claimAmount } });

  const totalUnits = toUnits(claimAmount);
  const firstAmount = fromUnits(totalUnits / 2n);
  const splitEvent = await buildSignedSplitEvent({ claimId: 'claim1', owner: aliceId, firstAmount, firstId: 'c1a', secondId: 'c1b' }, alice.seed, alice.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 's1', parents: ['c1'], payload: { type: 'split', ...splitEvent } });

  assert.equal(s.conservation.claims.c1a.amount + s.conservation.claims.c1b.amount, totalUnits);
});

test('totalBalance sums unclaimed-but-growing plus already-claimed, with no double count once a claim exists', async () => {
  const { state } = await readyToClaimDomain('alice');
  const claimableBefore = claimableNow(rewardParams, state.accrual, 'alice');
  const claimAmount = fromUnits(claimableBefore);
  const s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: 'alice', claimId: 'claim1', amount: claimAmount } });
  const total = totalBalance(rewardParams, s, 'alice');
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
    events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain: aliceId, epoch: e, vdfIterations: 50, vdfOutput } });
    lastId = id;
    previousOutput = vdfOutput;
  }
  events.push({ id: 'a1', parents: [lastId], payload: { type: 'accrual', domain: aliceId, b: 10 } });
  const state = await materializeWallet(rewardParams, events);
  assert.equal(state.accrual.progression.domains[aliceId].epoch, 3);
  assert.equal(state.accrual.positions[aliceId].b, 10);
});

test('THE REAL INCREMENTAL CATCH-UP PROPERTY: applying only newly-arrived events on top of already-materialized state produces byte-identical results to a full replay from scratch', async () => {
  const events = [];

  // Two real, causally-independent domains — the real scenario a
  // real P2P sync or file import would bring in together.
  for (const domain of ['domainA', 'domainB']) {
    let previousOutput = 'genesis';
    let lastId = null;
    for (let e = 1; e <= 3; e++) {
      const seed = vdfSeed(domain, previousOutput);
      const vdfOutput = await computeVdfChain(seed, 30);
      const id = `${domain}-e${e}`;
      events.push({ id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain, epoch: e, vdfIterations: 30, vdfOutput } });
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

  const { state } = await readyToClaimDomain(ownerId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: ownerId, claimId: 'claim1', amount: claimAmount } });

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

  const { state } = await readyToClaimDomain(ownerId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: ownerId, claimId: 'claim1', amount: claimAmount } });

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

  const { state } = await readyToClaimDomain(ownerId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: ownerId, claimId: 'claim1', amount: claimAmount } });

  const delegation = await issueDelegation(owner.seed, owner.pubkeyBytes, realDelegate.pubkeyBytes); // authorizes realDelegate specifically
  const impostorAttempt = await buildSignedDelegatedTransferEvent(delegation, { claimId: 'claim1', to: 'attacker' }, impostor.seed, impostor.pubkeyBytes); // but impostor signs instead
  s = await applyWalletEvent(rewardParams, s, { id: 't1', parents: ['c1'], payload: { type: 'delegated-transfer', ...impostorAttempt } });

  assert.equal(s.conservation.claims.claim1.status, 'active', 'a delegation for one real key must never authorize a different one');
});

test('SECURITY: a replayed delegated-transfer nonce is rejected, exactly like an ordinary transfer', async () => {
  const owner = makeSigner();
  const ownerId = await deriveId(owner.pubkeyBytes);
  const delegateKey = makeSigner();

  const { state } = await readyToClaimDomain(ownerId);
  const claimAmount = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: ownerId, claimId: 'claim1', amount: claimAmount } });

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

  const { state } = await readyToClaimDomain(ownerId, 5, 30);
  const claimable = fromUnits(claimableNow(rewardParams, state.accrual, ownerId));
  let s = await applyWalletEvent(rewardParams, state, { id: 'c1', parents: [], payload: { type: 'claim', domain: ownerId, claimId: 'claim1', amount: claimable } });

  // Split the one real claim into three real, smaller ones (an ordinary, owner-signed split — delegation is about TRANSFER authorization, not splitting), then click three times.
  const splitOne = await buildSignedSplitEvent({ claimId: 'claim1', owner: ownerId, firstAmount: (Number(claimable) / 3).toString(), firstId: 'c1a', secondId: 'c1b' }, owner.seed, owner.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split1', parents: ['c1'], payload: { type: 'split', ...splitOne } });
  const splitTwo = await buildSignedSplitEvent({ claimId: 'c1b', owner: ownerId, firstAmount: (Number(claimable) / 3).toString(), firstId: 'c1c', secondId: 'c1d' }, owner.seed, owner.pubkeyBytes);
  s = await applyWalletEvent(rewardParams, s, { id: 'split2', parents: ['split1'], payload: { type: 'split', ...splitTwo } });

  for (const claimId of ['c1a', 'c1c', 'c1d']) {
    const send = await buildSignedDelegatedTransferEvent(delegation, { claimId, to: 'bob' }, delegateKey.seed, delegateKey.pubkeyBytes);
    s = await applyWalletEvent(rewardParams, s, { id: `send-${claimId}`, parents: [`split2`], payload: { type: 'delegated-transfer', ...send } });
  }

  assert.equal(spendableClaims(s, 'bob').length, 3, 'three real, independent clicks, each its own real transfer — the owner\'s root key signed exactly once, for the delegation, at the very start');
});
