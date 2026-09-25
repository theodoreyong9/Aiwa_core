import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed, verifyVdfChain } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import {
  initialProgressionState, applyProgressionEvent, materializeProgression,
  progressionParents, buildSignedProgressionEvent,
} from '../src/progression.js';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A real Ed25519 keypair plus the domain id it really derives — every progression payload built with it can only ever be signed by this exact signer. */
async function realSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  const domain = await deriveId(pubkeyBytes);
  return { seed, pubkeyBytes, domain };
}

// buildSignedProgressionEvent() itself never embeds `type` — in real
// usage (createEvent) `type` lives at the outer wire-event level, only
// folded into payload later by adapt-event.js's own toReducerEvent.
// These unit tests bypass createEvent and hand-build {id, parents,
// payload} directly, so `type: 'progression'` has to be added here
// explicitly to get the identical reducer-shaped payload adaptation
// would have produced.
async function progressionPayload(signer, epoch, previousOutput = 'genesis', iterations = 50) {
  const seed = vdfSeed(signer.domain, previousOutput);
  const vdfOutput = await computeVdfChain(seed, iterations);
  return signedTestPayload(signer, { domain: signer.domain, epoch, vdfIterations: iterations, vdfOutput });
}

/** Same `type` restoration as progressionPayload(), for tests that need to hand-pick specific (often deliberately invalid) fields rather than a real, honestly-computed chain. */
async function signedTestPayload(signer, fields) {
  const signed = await buildSignedProgressionEvent(fields, signer.seed, signer.pubkeyBytes);
  return { type: 'progression', ...signed };
}

test('first transition is accepted', async () => {
  const signer = await realSigner();
  const payload = await progressionPayload(signer, 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain].epoch, 1);
  assert.equal(state.rejections.length, 0);
});

test('skipping an epoch is rejected', async () => {
  const signer = await realSigner();
  const payload = await progressionPayload(signer, 2);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain], undefined);
  assert.equal(state.rejections.length, 1);
});

test('a transition not chained to the last accepted one is rejected', async () => {
  const signer = await realSigner();
  let state = initialProgressionState();
  const p1 = await progressionPayload(signer, 1);
  state = await applyProgressionEvent(state, { id: 'e1', parents: [], payload: p1 });
  const p2 = await progressionPayload(signer, 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2', parents: [], payload: p2 });
  assert.equal(state.domains[signer.domain].epoch, 1);
});

test('a forked competing transition at the same epoch is rejected', async () => {
  const signer = await realSigner();
  let state = initialProgressionState();
  const p1 = await progressionPayload(signer, 1);
  state = await applyProgressionEvent(state, { id: 'e1', parents: [], payload: p1 });
  const p2a = await progressionPayload(signer, 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2a', parents: ['e1'], payload: p2a });
  const p2b = await progressionPayload(signer, 2, p1.vdfOutput);
  state = await applyProgressionEvent(state, { id: 'e2b', parents: ['e1'], payload: p2b });
  assert.equal(state.domains[signer.domain].lastId, 'e2a');
});

test('SECURITY: a transition with no real VDF proof is rejected', async () => {
  const signer = await realSigner();
  const payload = await signedTestPayload(signer, { domain: signer.domain, epoch: 1, vdfIterations: 50, vdfOutput: null });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain], undefined);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});

test('SECURITY: a fabricated VDF output is rejected', async () => {
  const signer = await realSigner();
  const payload = await signedTestPayload(signer, { domain: signer.domain, epoch: 1, vdfIterations: 50, vdfOutput: 'f'.repeat(64) });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain], undefined);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});

test('SECURITY: a real chain computed for fewer iterations than claimed is rejected', async () => {
  const signer = await realSigner();
  const shortcut = await computeVdfChain(vdfSeed(signer.domain, 'genesis'), 40);
  const payload = await signedTestPayload(signer, { domain: signer.domain, epoch: 1, vdfIterations: 50, vdfOutput: shortcut });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain], undefined);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});

test('SECURITY: a VDF proof computed for a different domain cannot be reused', async () => {
  const signer = await realSigner();
  const otherOutput = await computeVdfChain(vdfSeed('other', 'genesis'), 50);
  const payload = await signedTestPayload(signer, { domain: signer.domain, epoch: 1, vdfIterations: 50, vdfOutput: otherOutput });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload });
  assert.equal(state.domains[signer.domain], undefined);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});

test('SECURITY, THE REAL GAP FOUND AND CLOSED: a progression event naming a domain the real signer does not control is rejected — no more free advancement of someone else\'s progression', async () => {
  const attacker = await realSigner();
  const victim = await realSigner();
  // The attacker signs for real, but hand-crafts a payload naming the
  // victim's domain — the exact griefing vector: vdfSeed/vdfOutput are
  // both public, so anyone can compute a real, valid VDF proof for the
  // victim's own next epoch. Only the signature-vs-domain check below
  // can stop it.
  const seed = vdfSeed(victim.domain, 'genesis');
  const vdfOutput = await computeVdfChain(seed, 50);
  const forged = await signedTestPayload(attacker, { domain: victim.domain, epoch: 1, vdfIterations: 50, vdfOutput });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload: forged });
  assert.equal(state.domains[victim.domain], undefined, 'a real, valid VDF proof from anyone other than the domain itself must never advance that domain\'s own progression');
  assert.match(state.rejections[0].reason, /invalid signature/);
});

test('independent domains advance independently', async () => {
  const signerA = await realSigner();
  const signerB = await realSigner();
  let state = initialProgressionState();
  const pa = await progressionPayload(signerA, 1);
  const pb = await progressionPayload(signerB, 1);
  state = await applyProgressionEvent(state, { id: 'ea', parents: [], payload: pa });
  state = await applyProgressionEvent(state, { id: 'eb', parents: [], payload: pb });
  assert.equal(state.domains[signerA.domain].epoch, 1);
  assert.equal(state.domains[signerB.domain].epoch, 1);
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
  const signer = await realSigner();
  let state = initialProgressionState();
  let lastId = null;
  let previousOutput = 'genesis';
  for (let e = 1; e <= 4; e++) {
    const payload = await progressionPayload(signer, e, previousOutput);
    const id = `e${e}`;
    state = await applyProgressionEvent(state, { id, parents: lastId ? [lastId] : [], payload });
    lastId = id;
    previousOutput = payload.vdfOutput;
  }
  assert.equal(state.domains[signer.domain].epoch, 4);
  assert.equal(state.rejections.length, 0);
});

test('materializeProgression folds a real sequence via a real reducer-shaped event list', async () => {
  const signer = await realSigner();
  const p1 = await progressionPayload(signer, 1);
  const p2 = await progressionPayload(signer, 2, p1.vdfOutput);
  const events = [
    { id: 'e1', parents: [], payload: p1 },
    { id: 'e2', parents: ['e1'], payload: p2 },
  ];
  const state = await materializeProgression(events);
  assert.equal(state.domains[signer.domain].epoch, 2);
});

test('THE REAL INJECTION: a custom verifyFn is genuinely used instead of the default, real recomputation', async () => {
  let realVerifyCalls = 0;
  const spy = async (seed, iterations, output) => {
    realVerifyCalls += 1;
    return await verifyVdfChain(seed, iterations, output);
  };
  const signer = await realSigner();
  const payload = await progressionPayload(signer, 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload }, spy);
  assert.equal(realVerifyCalls, 1, 'the injected function must be the one actually invoked');
  assert.equal(state.domains[signer.domain].epoch, 1);
});

test('SECURITY: an injected verifyFn that always returns false rejects even a real, honestly-computed proof — the caller stays in full control', async () => {
  const alwaysFalse = async () => false;
  const signer = await realSigner();
  const payload = await progressionPayload(signer, 1);
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload }, alwaysFalse);
  assert.equal(state.domains[signer.domain], undefined);
  assert.equal(state.rejections.length, 1);
});

test('materializeProgression also accepts and genuinely uses a custom verifyFn', async () => {
  let calls = 0;
  const spy = async (seed, iterations, output) => { calls += 1; return await verifyVdfChain(seed, iterations, output); };
  const signer = await realSigner();
  const p1 = await progressionPayload(signer, 1);
  const p2 = await progressionPayload(signer, 2, p1.vdfOutput);
  const events = [{ id: 'e1', parents: [], payload: p1 }, { id: 'e2', parents: ['e1'], payload: p2 }];
  const state = await materializeProgression(events, spy);
  assert.equal(calls, 2);
  assert.equal(state.domains[signer.domain].epoch, 2);
});

test('SECURITY, THE REAL REGRESSION FOUND AND CLOSED: an explicit null verifyFn (never the same as omitting the argument) falls back to real, full VDF verification, instead of crashing', async () => {
  const signer = await realSigner();
  const p1 = await progressionPayload(signer, 1);
  const events = [{ id: 'e1', parents: [], payload: p1 }];
  const state = await applyProgressionEvent(initialProgressionState(), events[0], null);
  assert.equal(state.domains[signer.domain].epoch, 1, 'a real, valid progression event must still be accepted with an explicit null verifyFn, never crash');
  assert.equal(state.rejections.length, 0);
});

test('SECURITY: with an explicit null verifyFn, a real, invalid VDF proof is still genuinely rejected — the fallback is real verification, never a silent bypass', async () => {
  const signer = await realSigner();
  const fake = await signedTestPayload(signer, { domain: signer.domain, epoch: 1, vdfIterations: 30, vdfOutput: 'fabricated-never-computed' });
  const state = await applyProgressionEvent(initialProgressionState(), { id: 'e1', parents: [], payload: fake }, null);
  assert.equal(state.rejections.length, 1);
  assert.match(state.rejections[0].reason, /VDF proof does not verify/);
});

test('progressionParents: adds lastId only when heads do not already carry it, never duplicates', () => {
  assert.deepEqual(progressionParents(['h1'], null), ['h1'], 'nothing to add for a domain\'s first-ever progression event');
  assert.deepEqual(progressionParents(['h1'], 'h1'), ['h1'], 'already the head — must not duplicate');
  assert.deepEqual(progressionParents(['h1'], 'p0'), ['h1', 'p0'], 'something else intervened — the real last progression id must be added back in');
  assert.deepEqual(progressionParents(['h1', 'p0'], 'p0'), ['h1', 'p0'], 'already present among multiple heads — must not duplicate');
});

test('THE REAL REGRESSION FOUND AND CLOSED: a progression event still chains correctly after an unrelated event (e.g. an accrual) became the log head in between — the exact real sequence recordCommitment() then advanceProgress() produces', async () => {
  const signer = await realSigner();
  const domain = signer.domain;
  let state = initialProgressionState();

  const p1 = await progressionPayload(signer, 1);
  state = await applyProgressionEvent(state, { id: 'prog1', parents: [], payload: p1 });
  assert.equal(state.domains[domain].epoch, 1);

  // An unrelated, non-progression event becomes the log's sole head —
  // exactly what recordCommitment() does in real usage. progression.js
  // never even sees it (non-progression events pass through unchanged),
  // but a REAL event builder must still route parents through
  // progressionParents(), using the domain's real current head plus its
  // own real last accepted progression id.
  const realHeadsAfterAccrual = ['accrual1'];

  const p2 = await progressionPayload(signer, 2, p1.vdfOutput);
  const parents = progressionParents(realHeadsAfterAccrual, state.domains[domain].lastId);
  assert.deepEqual(parents, ['accrual1', 'prog1'], 'must explicitly restore the real chain to the last progression event');
  state = await applyProgressionEvent(state, { id: 'prog2', parents, payload: p2 });

  assert.equal(state.domains[domain].epoch, 2, 'must NOT get stuck at epoch 1 — this is the real bug that was found and fixed');
  assert.equal(state.rejections.length, 0);
});
