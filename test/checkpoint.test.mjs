import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { EventLog } from '../src/event-log.js';
import { generateIdentity, identityFromSecretKey } from '../src/identity.js';
import { createEvent } from '../src/event.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { initialWalletState, materializeWallet } from '../src/wallet.js';
import { buildSignedAccrualEvent } from '../src/accrual.js';
import { toReducerEvents } from '../src/adapt-event.js';
import { progressionParents } from '../src/progression.js';
import {
  serializeWalletState, deserializeWalletState, buildCheckpointEvent,
  verifyCheckpoint, checkpointWalletState, findLatestCheckpoint,
} from '../src/checkpoint.js';

const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A real signer plus the real Identity wrapping it — needed here because buildSignedAccrualEvent takes raw seed/pubkey bytes while createEvent/buildCheckpointEvent take a real Identity. */
async function realOwner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  const identity = await identityFromSecretKey(toHex(seed));
  return { seed, pubkeyBytes, identity };
}

test('serializeWalletState/deserializeWalletState round-trip real BigInt fields exactly', () => {
  const state = { accrual: { balances: { d: 12345678901234567890n } }, conservation: { claims: { c1: { amount: 1000000000000000000n } } } };
  const round = deserializeWalletState(serializeWalletState(state));
  assert.equal(round.accrual.balances.d, 12345678901234567890n);
  assert.equal(round.conservation.claims.c1.amount, 1000000000000000000n);
  assert.equal(typeof round.accrual.balances.d, 'bigint');
});

test('a real self-signed checkpoint verifies', async () => {
  const identity = await generateIdentity();
  const state = initialWalletState();
  const checkpoint = await buildCheckpointEvent(identity, {
    logDomain: 'aiwa', parents: [], coveredHeads: [], walletState: state,
  });
  assert.equal(verifyCheckpoint(checkpoint), true);
  const recovered = checkpointWalletState(checkpoint);
  assert.deepEqual(recovered, state);
});

test('SECURITY: a checkpoint claiming a domain the real signer does not control is rejected', async () => {
  const attacker = await generateIdentity();
  const victim = await generateIdentity();
  // The attacker signs for real, but hand-crafts a payload naming the victim's domain.
  const forged = await createEvent(attacker, {
    domain: 'aiwa', parents: [], type: 'checkpoint',
    payload: { domain: victim.id, coveredHeads: [], walletState: serializeWalletState(initialWalletState()) },
  });
  assert.equal(verifyCheckpoint(forged), false, 'a real signature from anyone other than the domain itself must never make a checkpoint trustworthy');
});

test('a non-checkpoint event is never mistaken for one', async () => {
  const identity = await generateIdentity();
  const event = await createEvent(identity, { domain: 'aiwa', parents: [], type: 'transfer', payload: { domain: identity.id } });
  assert.equal(verifyCheckpoint(event), false);
  assert.equal(checkpointWalletState(event), null);
});

/**
 * Appends `count` real progression events, exactly the way real
 * production code (aiwa-lib's advanceProgress()) does: parents are the
 * log's own real current heads (`resumeParent`, e.g. an intervening
 * accrual or checkpoint event — whatever is actually last in the log),
 * PLUS — via progressionParents() — the domain's own real last accepted
 * progression id (`lastProgressionId`), so the causal-chain check in
 * progression.js keeps passing even when something else was published
 * for this domain since. Only the FIRST event of a run needs that;
 * every event after it is a pure progression-to-progression chain.
 */
async function appendProgressionRun(log, owner, domain, resumeParent, lastProgressionId, previousOutput, startEpoch, count) {
  let lastId = lastProgressionId;
  let epoch = startEpoch;
  let output = previousOutput;
  for (let i = 0; i < count; i++) {
    epoch += 1;
    const vdfOutput = await computeVdfChain(vdfSeed(domain, output), 30);
    const parents = i === 0 ? progressionParents(resumeParent ? [resumeParent] : [], lastId) : [lastId];
    const ev = await createEvent(owner.identity, { domain: 'aiwa', parents, type: 'progression', payload: { domain, epoch, vdfIterations: 30, vdfOutput } });
    await log.append(ev);
    lastId = ev.id;
    output = vdfOutput;
  }
  return { lastId, epoch, output };
}

async function fullReplayOf(log) {
  const ids = await log.backend.allIds();
  const events = await Promise.all(ids.map((id) => log.get(id)));
  events.sort((a, b) => a.createdAt - b.createdAt);
  return materializeWallet(rewardParams, toReducerEvents(events));
}

test('THE REAL PRUNE-AND-RESUME PROPERTY: materializing from a checkpoint + only later events matches what continuing to replay the unpruned history from genesis would give', async () => {
  const owner = await realOwner();
  const domain = owner.identity.id;
  const log = new EventLog();

  // A real, mixed history: progression, a real signed accrual, more progression.
  let run = await appendProgressionRun(log, owner, domain, null, null, 'genesis', 0, 5);
  const realAccrual = await buildSignedAccrualEvent({ domain, b: 100 }, owner.seed, owner.pubkeyBytes);
  const accrualEvent = await createEvent(owner.identity, { domain: 'aiwa', parents: [run.lastId], type: 'accrual', payload: realAccrual });
  await log.append(accrualEvent);
  run = await appendProgressionRun(log, owner, domain, accrualEvent.id, run.lastId, run.output, run.epoch, 5);

  // The real state right here — this is what the checkpoint will embed.
  const stateAtCheckpoint = await fullReplayOf(log);
  const headsAtCheckpoint = await log.head();
  const checkpointEvent = await buildCheckpointEvent(owner.identity, {
    logDomain: 'aiwa', parents: headsAtCheckpoint, coveredHeads: headsAtCheckpoint, walletState: stateAtCheckpoint,
  });
  await log.append(checkpointEvent);

  // More real history after the checkpoint. In the real (unpruned) DAG
  // this baseline replays, the checkpoint event itself never updates
  // progression.domains[domain].lastId (it's a no-op payload.type to
  // every reducer) — so the true chain-from id here is still the real
  // pre-checkpoint progression event (run.lastId from the prior run),
  // exactly like real production code would see before ever consulting
  // a checkpoint.
  run = await appendProgressionRun(log, owner, domain, checkpointEvent.id, run.lastId, run.output, run.epoch, 5);

  // The real, independent baseline: a full replay of the identical, still-unpruned log.
  const expectedFinal = await fullReplayOf(log);

  // THE REAL PROPERTY: prune everything the checkpoint covers, then
  // materialize using ONLY the checkpoint's own embedded state plus
  // whatever real events are left — must equal that same baseline.
  const prunedCount = await log.pruneBeforeCheckpoint(checkpointEvent.id);
  assert.ok(prunedCount > 0, 'pruning a real, non-trivial history must actually remove something');
  assert.equal(await log.has(accrualEvent.id), false, 'pruned events must really be gone from the backend');
  assert.equal(await log.has(checkpointEvent.id), true, 'the checkpoint itself must survive its own prune');

  const found = await findLatestCheckpoint(log, domain);
  assert.equal(found.id, checkpointEvent.id);
  const base = checkpointWalletState(found);

  const remainingIds = await log.backend.allIds();
  const remainingEvents = (await Promise.all(remainingIds.map((id) => log.get(id))))
    .filter((e) => e.id !== checkpointEvent.id);
  remainingEvents.sort((a, b) => a.createdAt - b.createdAt);
  const resumed = await materializeWallet(rewardParams, toReducerEvents(remainingEvents), null, undefined, {}, base);

  // Real expected values asserted directly (not just equality against
  // `expectedFinal`) — 15 real progression events were appended above
  // (5 + 5 + 5), and a baseline that were ALSO silently stuck partway
  // would make an equality-only check pass while masking a real bug,
  // exactly what happened here before progressionParents() existed.
  assert.equal(expectedFinal.accrual.progression.domains[domain].epoch, 15, 'the unpruned baseline itself must really reach epoch 15');
  assert.equal(expectedFinal.accrual.progression.rejections.length, 0, 'the unpruned baseline must have zero real rejections');
  assert.equal(resumed.accrual.progression.domains[domain].epoch, 15);
  assert.equal(resumed.accrual.progression.rejections.length, 0);

  assert.equal(resumed.accrual.progression.domains[domain].epoch, expectedFinal.accrual.progression.domains[domain].epoch);
  assert.equal(resumed.accrual.positions[domain].b, expectedFinal.accrual.positions[domain].b);
  assert.equal(resumed.accrual.positions[domain].lastActionEpoch, expectedFinal.accrual.positions[domain].lastActionEpoch);
});

test('EventLog.append accepts a valid checkpoint even when its own declared parents are missing — the real state a fresh peer is in after receiving a pruned log', async () => {
  const owner = await generateIdentity();
  const fakeParentId = 'never-actually-sent-to-this-peer';
  const checkpoint = await buildCheckpointEvent(owner, {
    logDomain: 'aiwa', parents: [fakeParentId], coveredHeads: [fakeParentId], walletState: initialWalletState(),
  });
  const freshLog = new EventLog();
  await assert.doesNotReject(freshLog.append(checkpoint), 'a real, valid checkpoint must be acceptable as a new root, even with an unknown declared parent');
  assert.equal(await freshLog.has(checkpoint.id), true);
});

test('SECURITY: an ordinary (non-checkpoint) event with a missing parent is still rejected, the checkpoint exception never leaks to other event types', async () => {
  const owner = await generateIdentity();
  const ordinary = await createEvent(owner, { domain: 'aiwa', parents: ['some-unknown-parent'], type: 'transfer', payload: {} });
  const log = new EventLog();
  await assert.rejects(log.append(ordinary), /not yet known/);
});

test('SECURITY: pruneBeforeCheckpoint refuses a real event id that is not actually a valid checkpoint', async () => {
  const owner = await generateIdentity();
  const log = new EventLog();
  const ordinary = await createEvent(owner, { domain: 'aiwa', parents: [], type: 'transfer', payload: {} });
  await log.append(ordinary);
  await assert.rejects(log.pruneBeforeCheckpoint(ordinary.id), /not a real, self-authored checkpoint/);
});
