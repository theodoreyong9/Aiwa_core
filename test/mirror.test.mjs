import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '@aiwa/record';
import {
  initialMirrorState, applyMirrorEvent, materializeMirror,
  deriveSourceEpochLookup, computeResidualDiversity,
} from '../src/mirror.js';

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}

function canonicalMessage({ domain, epoch, kind, receivedFrom }) {
  const sorted = [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId));
  return JSON.stringify({ domain, epoch, kind, receivedFrom: sorted });
}
function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function signCommitment(signer, fields) {
  const message = new TextEncoder().encode(canonicalMessage(fields));
  const signature = ed25519.sign(message, signer.seed);
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(signer.pubkeyBytes) };
}

test('an empty commitment is accepted', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'empty', receivedFrom: [] });
  const state = await applyMirrorEvent(initialMirrorState(), { id: 'e1', payload: { type: 'reception', ...payload } }, () => null);
  assert.equal(state.commitments[domain].length, 1);
  assert.equal(state.rejections.length, 0);
});

test("kind='empty' with a non-empty receivedFrom is rejected", async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'empty', receivedFrom: [{ sourceDomain: 'x', eventId: 'e' }] });
  const state = await applyMirrorEvent(initialMirrorState(), { id: 'e1', payload: { type: 'reception', ...payload } }, () => 1);
  assert.equal(state.rejections.length, 1);
});

test('SECURITY: a commitment with a forged signature is rejected', async () => {
  const signer = makeSigner();
  const attacker = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const message = new TextEncoder().encode(canonicalMessage({ domain, epoch: 1, kind: 'empty', receivedFrom: [] }));
  const wrongSignature = ed25519.sign(message, attacker.seed);
  const state = await applyMirrorEvent(initialMirrorState(), {
    id: 'e1', payload: { type: 'reception', domain, epoch: 1, kind: 'empty', receivedFrom: [], signature: toHex(wrongSignature), signerPubkey: toHex(signer.pubkeyBytes) },
  }, () => null);
  assert.equal(state.rejections.length, 1);
});

test('SECURITY: tampering with receivedFrom after signing invalidates the signature', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'x', eventId: 'e1' }] });
  const tampered = { ...payload, receivedFrom: [{ sourceDomain: 'y', eventId: 'e2' }] };
  const state = await applyMirrorEvent(initialMirrorState(), { id: 'ev1', payload: { type: 'reception', ...tampered } }, () => 1);
  assert.equal(state.rejections.length, 1);
});

test('a full commitment referencing a real, existing source event is accepted', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'real-event' }] });
  const lookup = (source, id) => (source === 'c' && id === 'real-event' ? 5 : null);
  const state = await applyMirrorEvent(initialMirrorState(), { id: 'e1', payload: { type: 'reception', ...payload } }, lookup);
  assert.equal(state.rejections.length, 0);
});

test('SECURITY: a full commitment referencing a nonexistent event is rejected', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'fake-event' }] });
  const state = await applyMirrorEvent(initialMirrorState(), { id: 'e1', payload: { type: 'reception', ...payload } }, () => null);
  assert.equal(state.rejections.length, 1);
});

test('SECURITY: reception monotonicity — claiming an earlier state than previously claimed is rejected', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  let state = initialMirrorState();
  const p1 = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-10' }] });
  state = await applyMirrorEvent(state, { id: 'ev1', payload: { type: 'reception', ...p1 } }, () => 10);
  const p2 = await signCommitment(signer, { domain, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-5' }] });
  state = await applyMirrorEvent(state, { id: 'ev2', payload: { type: 'reception', ...p2 } }, () => 5);
  assert.equal(state.rejections.length, 1);
  assert.equal(state.maxSeenEpoch[domain].c, 10, 'the real, prior max must be preserved, not overwritten');
});

test('reception monotonicity: claiming a later or equal state is accepted', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  let state = initialMirrorState();
  const p1 = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-5' }] });
  state = await applyMirrorEvent(state, { id: 'ev1', payload: { type: 'reception', ...p1 } }, () => 5);
  const p2 = await signCommitment(signer, { domain, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-10' }] });
  state = await applyMirrorEvent(state, { id: 'ev2', payload: { type: 'reception', ...p2 } }, () => 10);
  assert.equal(state.rejections.length, 0);
  assert.equal(state.maxSeenEpoch[domain].c, 10);
});

test('monotonicity is tracked independently per source domain', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  let state = initialMirrorState();
  const p1 = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'c-at-10' }] });
  state = await applyMirrorEvent(state, { id: 'ev1', payload: { type: 'reception', ...p1 } }, () => 10);
  const p2 = await signCommitment(signer, { domain, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'd', eventId: 'd-at-1' }] });
  state = await applyMirrorEvent(state, { id: 'ev2', payload: { type: 'reception', ...p2 } }, () => 1);
  assert.equal(state.rejections.length, 0);
});

test('materializeMirror folds a real sequence and still catches a monotonicity violation', async () => {
  const signer = makeSigner();
  const domain = await deriveId(signer.pubkeyBytes);
  const p1 = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-10' }] });
  const p2 = await signCommitment(signer, { domain, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'c', eventId: 'e-at-3' }] });
  const events = [{ id: 'ev1', payload: { type: 'reception', ...p1 } }, { id: 'ev2', payload: { type: 'reception', ...p2 } }];
  const lookup = (source, id) => (id === 'e-at-10' ? 10 : id === 'e-at-3' ? 3 : null);
  const state = await materializeMirror(events, lookup);
  assert.equal(state.rejections.length, 1);
});

test('deriveSourceEpochLookup returns the real epoch when the target is a progression event', () => {
  const events = [{ id: 'p1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 3 } }];
  const lookup = deriveSourceEpochLookup(events);
  assert.equal(lookup('d', 'p1'), 3);
});

test('deriveSourceEpochLookup walks ancestors for the highest real progression epoch', () => {
  const events = [
    { id: 'p1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 1 } },
    { id: 'p2', parents: ['p1'], payload: { type: 'progression', domain: 'd', epoch: 2 } },
    { id: 'other', parents: ['p2'], payload: { type: 'other', domain: 'd' } },
  ];
  const lookup = deriveSourceEpochLookup(events);
  assert.equal(lookup('d', 'other'), 2);
});

test('deriveSourceEpochLookup returns null for an event misattributed to a different domain', () => {
  const events = [{ id: 'p1', parents: [], payload: { type: 'progression', domain: 'd', epoch: 3 } }];
  const lookup = deriveSourceEpochLookup(events);
  assert.equal(lookup('other-domain', 'p1'), null);
});

test('deriveSourceEpochLookup returns null for a nonexistent event id', () => {
  const lookup = deriveSourceEpochLookup([]);
  assert.equal(lookup('d', 'ghost'), null);
});

test('a real event with no progression ancestors is legitimate epoch-0 state, not absence', () => {
  const events = [{ id: 'reg', parents: [], payload: { type: 'identity-register', domain: 'd' } }];
  const lookup = deriveSourceEpochLookup(events);
  assert.equal(lookup('d', 'reg'), 0);
});

test('computeResidualDiversity is 0 with no commitments', () => {
  const result = computeResidualDiversity(initialMirrorState(), 'ghost');
  assert.equal(result.entropy, 0);
});

test('a domain with a wide, organic spread of counterparties scores high entropy', () => {
  const state = { commitments: { d: [{ receivedFrom: [{ sourceDomain: 'a', eventId: 'e' }, { sourceDomain: 'b', eventId: 'e' }, { sourceDomain: 'c', eventId: 'e' }] }] } };
  const wide = computeResidualDiversity(state, 'd');
  const narrowState = { commitments: { d: [{ receivedFrom: [{ sourceDomain: 'a', eventId: 'e1' }, { sourceDomain: 'a', eventId: 'e2' }, { sourceDomain: 'a', eventId: 'e3' }] }] } };
  const narrow = computeResidualDiversity(narrowState, 'd');
  assert.ok(wide.entropy > narrow.entropy);
});

test('THE REAL INCREMENTAL CATCH-UP PROPERTY: applying only newly-arrived real reception events on top of already-materialized state produces byte-identical results to a full replay from scratch', async () => {
  const signerA = makeSigner();
  const domainA = await deriveId(signerA.pubkeyBytes);
  const signerB = makeSigner();
  const domainB = await deriveId(signerB.pubkeyBytes);

  const events = [];
  const p1 = await signCommitment(signerA, { domain: domainA, epoch: 1, kind: 'empty', receivedFrom: [] });
  events.push({ id: 'a1', payload: { type: 'reception', ...p1 } });
  const p2 = await signCommitment(signerA, { domain: domainA, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'src', eventId: 'src-e' }] });
  events.push({ id: 'a2', payload: { type: 'reception', ...p2 } });
  const p3 = await signCommitment(signerB, { domain: domainB, epoch: 1, kind: 'empty', receivedFrom: [] });
  events.push({ id: 'b1', payload: { type: 'reception', ...p3 } });

  const lookup = () => 5; // a real, fixed, resolvable epoch for any real source reference

  const fullReplay = await materializeMirror(events, lookup);

  const coveredIds = new Set(['a1']);
  let incremental = await materializeMirror(events.filter((e) => coveredIds.has(e.id)), lookup);
  for (const event of events.filter((e) => !coveredIds.has(e.id))) {
    incremental = await applyMirrorEvent(incremental, event, lookup);
  }

  assert.deepEqual(fullReplay, incremental, 'a real, partial-then-incremental catch-up must produce an identical real Mirror state to a full replay');
});
