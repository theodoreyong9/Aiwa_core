import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '@aiwa/record';
import { initialMirrorState, applyMirrorEvent } from '../src/mirror.js';
import { initialIdentityCostState, registerIdentityCost } from '../src/identity-cost.js';
import { computeCausalTick, checkCausalConsistency } from '../src/causal-tick.js';

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}
function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function canonicalMessage({ domain, epoch, kind, receivedFrom }) {
  const sorted = [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId));
  return JSON.stringify({ domain, epoch, kind, receivedFrom: sorted });
}
async function signCommitment(signer, fields) {
  const message = new TextEncoder().encode(canonicalMessage(fields));
  const signature = ed25519.sign(message, signer.seed);
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(signer.pubkeyBytes) };
}
function fundedIdentityCost(state, domain, lamports) {
  const result = registerIdentityCost(state, { domain, tx: { signature: `sig-${domain}`, err: null, incineratorBalanceDeltaLamports: lamports, commitment: 'finalized', slot: 1 } });
  return result.state;
}
function deriveSourceEpochLookupOverride(orderedEvents) {
  return (sourceDomain, eventId) => {
    const ev = orderedEvents.find((e) => e.id === eventId);
    return ev && ev.payload.domain === sourceDomain ? ev.payload.epoch : null;
  };
}

test('a domain with no external observers has no causal tick — a real, honest absence (bottom)', async () => {
  const result = await computeCausalTick(initialMirrorState(), initialIdentityCostState(), [], 'ghost');
  assert.equal(result, null);
});

test('a single, real, funded observer produces a real causal tick matching what it observed', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEvent = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  let identityCostState = fundedIdentityCost(initialIdentityCostState(), observerDomain, 1000);
  const payload = await signCommitment(signer, { domain: observerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  const mirrorState = await applyMirrorEvent(initialMirrorState(), { id: 'm1', payload: { type: 'reception', ...payload } }, deriveSourceEpochLookupOverride([targetEvent]));

  const result = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  assert.equal(result.tick, 5);
  assert.equal(result.totalWeight, 1000);
});

test('SECURITY: an observer with zero real burn contributes zero weight, even with a real, validly-signed commitment', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEvent = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  const identityCostState = initialIdentityCostState();
  const payload = await signCommitment(signer, { domain: observerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  const mirrorState = await applyMirrorEvent(initialMirrorState(), { id: 'm1', payload: { type: 'reception', ...payload } }, deriveSourceEpochLookupOverride([targetEvent]));

  const result = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  assert.equal(result, null, 'a real signature with zero real committed capital must contribute nothing');
});

test('SECURITY: real majority weight determines the tick even against a funded but minority adversary', async () => {
  const targetEvent = { id: 'e100', parents: [], payload: { type: 'progression', domain: 'target', epoch: 100 } };
  const fakeTargetEvent = { id: 'e-fake-999', parents: [], payload: { type: 'progression', domain: 'target', epoch: 999999 } };
  const orderedEvents = [targetEvent, fakeTargetEvent];

  let mirrorState = initialMirrorState();
  let identityCostState = initialIdentityCostState();
  const lookup = deriveSourceEpochLookupOverride(orderedEvents);

  for (let i = 0; i < 3; i++) {
    const signer = makeSigner();
    const domain = await deriveId(signer.pubkeyBytes);
    identityCostState = fundedIdentityCost(identityCostState, domain, 10000);
    const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e100' }] });
    mirrorState = await applyMirrorEvent(mirrorState, { id: `m-honest-${i}`, payload: { type: 'reception', ...payload } }, lookup);
  }
  const attacker = makeSigner();
  const attackerDomain = await deriveId(attacker.pubkeyBytes);
  identityCostState = fundedIdentityCost(identityCostState, attackerDomain, 9999);
  const attackPayload = await signCommitment(attacker, { domain: attackerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e-fake-999' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'm-attacker', payload: { type: 'reception', ...attackPayload } }, lookup);

  const result = await computeCausalTick(mirrorState, identityCostState, orderedEvents, 'target');
  assert.equal(result.tick, 100, `real honest majority weight must win — got ${result.tick}`);
});

test('checkCausalConsistency is trivially consistent with no evidence yet', () => {
  const { consistent, gap } = checkCausalConsistency(500, null, 5);
  assert.equal(consistent, true);
  assert.equal(gap, null);
});

test('checkCausalConsistency flags a real, large gap between self-reported and corroborated epoch', () => {
  const { consistent, gap } = checkCausalConsistency(500, { tick: 10 }, 5);
  assert.equal(consistent, false);
  assert.equal(gap, 490);
});

test('checkCausalConsistency accepts a self-reported epoch within real tolerance', () => {
  const { consistent } = checkCausalConsistency(12, { tick: 10 }, 5);
  assert.equal(consistent, true);
});

test('computeCausalTick reports a real interval, not just a point — spread across disagreeing observers', async () => {
  const targetEvent98 = { id: 'e98', parents: [], payload: { type: 'progression', domain: 'target', epoch: 98 } };
  const targetEvent102 = { id: 'e102', parents: [], payload: { type: 'progression', domain: 'target', epoch: 102 } };
  const orderedEvents = [targetEvent98, targetEvent102];
  const lookup = deriveSourceEpochLookupOverride(orderedEvents);

  let mirrorState = initialMirrorState();
  let identityCostState = initialIdentityCostState();
  const signerA = makeSigner();
  const domainA = await deriveId(signerA.pubkeyBytes);
  identityCostState = fundedIdentityCost(identityCostState, domainA, 1000);
  const payloadA = await signCommitment(signerA, { domain: domainA, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e98' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'mA', payload: { type: 'reception', ...payloadA } }, lookup);

  const signerB = makeSigner();
  const domainB = await deriveId(signerB.pubkeyBytes);
  identityCostState = fundedIdentityCost(identityCostState, domainB, 1000);
  const payloadB = await signCommitment(signerB, { domain: domainB, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e102' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'mB', payload: { type: 'reception', ...payloadB } }, lookup);

  const result = await computeCausalTick(mirrorState, identityCostState, orderedEvents, 'target');
  assert.deepEqual(result.interval, [98, 102]);
});

test('HARDWARE IS OPTIONAL: computeCausalTick produces the identical tick with or without hardware attestation data', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEvent = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  const identityCostState = fundedIdentityCost(initialIdentityCostState(), observerDomain, 1000);
  const payload = await signCommitment(signer, { domain: observerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  const mirrorState = await applyMirrorEvent(initialMirrorState(), { id: 'm1', payload: { type: 'reception', ...payload } }, deriveSourceEpochLookupOverride([targetEvent]));

  const withoutHardware = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  const withHardware = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target', {});
  assert.equal(withoutHardware.tick, withHardware.tick, 'hardware data (or its absence) must never change the tick itself');
  assert.equal(withoutHardware.hardwareBackedWeight, 0);
});

test('HARDWARE IS AN OPTIONAL SIGNAL, NEVER A WEIGHT: a hardware-backed observer with the same burn contributes the identical weight as one without', async () => {
  const { issueHardwareRoot, bindHardwareRoot } = await import('../src/hardware-attestation.js');
  function makeKeypair() {
    const s = makeSigner();
    return { secretKey: new Uint8Array([...s.seed, ...s.pubkeyBytes]), publicKey: { toBytes: () => s.pubkeyBytes } };
  }

  const targetEvent = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  const lookup = deriveSourceEpochLookupOverride([targetEvent]);

  const signerA = makeSigner();
  const domainA = await deriveId(signerA.pubkeyBytes);
  const signerB = makeSigner();
  const domainB = await deriveId(signerB.pubkeyBytes);

  let identityCostState = fundedIdentityCost(initialIdentityCostState(), domainA, 1000);
  identityCostState = fundedIdentityCost(identityCostState, domainB, 1000);

  let mirrorState = initialMirrorState();
  const payloadA = await signCommitment(signerA, { domain: domainA, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'mA', payload: { type: 'reception', ...payloadA } }, lookup);
  const payloadB = await signCommitment(signerB, { domain: domainB, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'mB', payload: { type: 'reception', ...payloadB } }, lookup);

  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  async function realAttestation(target) {
    const root = makeSigner();
    const issuance = await issueHardwareRoot(origin, originDomain, root.pubkeyBytes);
    const binding = await bindHardwareRoot(root.seed, root.pubkeyBytes, target);
    return { issuance, binding };
  }
  const hardwareAttestations = { [domainB]: [await realAttestation(domainB), await realAttestation(domainB)] };

  const result = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target', hardwareAttestations);
  assert.equal(result.totalWeight, 2000, 'both observers contribute the identical, real burn-based weight regardless of hardware');
  assert.equal(result.hardwareBackedWeight, 1000, 'only the real, hardware-attested observer is reported as hardware-backed');
  assert.equal(result.hardwareBackedObservers, 1);
});

test('SECURITY, THE REAL BUG FOUND AND FIXED: replaying the identical reception commitment gives zero additional influence', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEvent = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  const identityCostState = fundedIdentityCost(initialIdentityCostState(), observerDomain, 1000);
  const lookup = deriveSourceEpochLookupOverride([targetEvent]);

  let mirrorState = initialMirrorState();
  for (let epoch = 1; epoch <= 2; epoch++) {
    const payload = await signCommitment(signer, { domain: observerDomain, epoch, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
    mirrorState = await applyMirrorEvent(mirrorState, { id: `m${epoch}`, payload: { type: 'reception', ...payload } }, lookup);
  }

  const result = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  assert.equal(result.totalWeight, 1000, 'the real observer\'s real burn must be counted exactly once, never once per historical mention of the same fact');
  assert.equal(result.observationCount, 1);
});

test('an observer who has evolved their real knowledge over time contributes their single, most-recent observation, not an accumulation', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEventOld = { id: 'e5', parents: [], payload: { type: 'progression', domain: 'target', epoch: 5 } };
  const targetEventNew = { id: 'e9', parents: [], payload: { type: 'progression', domain: 'target', epoch: 9 } };
  const identityCostState = fundedIdentityCost(initialIdentityCostState(), observerDomain, 1000);
  const lookup = deriveSourceEpochLookupOverride([targetEventOld, targetEventNew]);

  let mirrorState = initialMirrorState();
  const p1 = await signCommitment(signer, { domain: observerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e5' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'm1', payload: { type: 'reception', ...p1 } }, lookup);
  const p2 = await signCommitment(signer, { domain: observerDomain, epoch: 2, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e9' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'm2', payload: { type: 'reception', ...p2 } }, lookup);

  const result = await computeCausalTick(mirrorState, identityCostState, [targetEventOld, targetEventNew], 'target');
  assert.equal(result.observationCount, 1, 'one real observer, one real current-knowledge estimate — never accumulated across their own history');
  assert.equal(result.tick, 9, 'the more recent, more advanced real observation is what a single real observer\'s current knowledge actually is');
  assert.equal(result.totalWeight, 1000);
});

test('DOMAIN INVARIANCE: computeCausalTick is a pure function — identical evidence always produces the identical result, regardless of which domain asks', async () => {
  const signer = makeSigner();
  const observerDomain = await deriveId(signer.pubkeyBytes);
  const targetEvent = { id: 'e7', parents: [], payload: { type: 'progression', domain: 'target', epoch: 7 } };
  const identityCostState = fundedIdentityCost(initialIdentityCostState(), observerDomain, 1000);
  const payload = await signCommitment(signer, { domain: observerDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e7' }] });
  const mirrorState = await applyMirrorEvent(initialMirrorState(), { id: 'm1', payload: { type: 'reception', ...payload } }, deriveSourceEpochLookupOverride([targetEvent]));

  const fromEarth = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  const fromMars = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'target');
  assert.deepEqual(fromEarth, fromMars, 'the identical real evidence must produce the identical real result no matter who computes it');
});

test('SECURITY, THE REAL SYBIL PROPERTY: many low-burn identities do not out-weigh fewer, well-funded real domains', async () => {
  const targetEvent = { id: 'e50', parents: [], payload: { type: 'progression', domain: 'target', epoch: 50 } };
  const fakeEvent = { id: 'e-fake', parents: [], payload: { type: 'progression', domain: 'target', epoch: 999999 } };
  const orderedEvents = [targetEvent, fakeEvent];
  const lookup = deriveSourceEpochLookupOverride(orderedEvents);

  let mirrorState = initialMirrorState();
  let identityCostState = initialIdentityCostState();

  for (let i = 0; i < 2; i++) {
    const signer = makeSigner();
    const domain = await deriveId(signer.pubkeyBytes);
    identityCostState = fundedIdentityCost(identityCostState, domain, 50000);
    const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e50' }] });
    mirrorState = await applyMirrorEvent(mirrorState, { id: `honest-${i}`, payload: { type: 'reception', ...payload } }, lookup);
  }

  for (let i = 0; i < 20; i++) {
    const signer = makeSigner();
    const domain = await deriveId(signer.pubkeyBytes);
    identityCostState = fundedIdentityCost(identityCostState, domain, 1000);
    const payload = await signCommitment(signer, { domain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'target', eventId: 'e-fake' }] });
    mirrorState = await applyMirrorEvent(mirrorState, { id: `sybil-${i}`, payload: { type: 'reception', ...payload } }, lookup);
  }

  const result = await computeCausalTick(mirrorState, identityCostState, orderedEvents, 'target');
  assert.equal(result.tick, 50, `20 low-burn identities (${20 * 1000} total) must not outweigh 2 real, well-funded domains (${2 * 50000} total) — got tick=${result.tick}`);
});

test('THE EARTH/MARS TEST: two domains with genuinely different local progressions compute the identical comparable coordinate for a shared, externally-observed target', async () => {
  // Earth and Mars never synchronize with each other at all — they
  // only both happen to have real, signed reception commitments about
  // the SAME real target domain, each independently derived from the
  // identical underlying causal content (content-addressed, so
  // transport path never matters).
  const targetEvent = { id: 'e42', parents: [], payload: { type: 'progression', domain: 'shared-target', epoch: 42 } };
  const lookup = deriveSourceEpochLookupOverride([targetEvent]);

  const earthSigner = makeSigner();
  const earthDomain = await deriveId(earthSigner.pubkeyBytes);
  const marsSigner = makeSigner();
  const marsDomain = await deriveId(marsSigner.pubkeyBytes);

  // Earth and Mars each really burned different, real amounts —
  // their own local histories are otherwise completely unrelated
  // (10,000 vs 7,000 "local progression", never compared directly).
  let identityCostState = fundedIdentityCost(initialIdentityCostState(), earthDomain, 10000);
  identityCostState = fundedIdentityCost(identityCostState, marsDomain, 7000);

  let mirrorState = initialMirrorState();
  const earthPayload = await signCommitment(earthSigner, { domain: earthDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'shared-target', eventId: 'e42' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'earth-obs', payload: { type: 'reception', ...earthPayload } }, lookup);
  const marsPayload = await signCommitment(marsSigner, { domain: marsDomain, epoch: 1, kind: 'full', receivedFrom: [{ sourceDomain: 'shared-target', eventId: 'e42' }] });
  mirrorState = await applyMirrorEvent(mirrorState, { id: 'mars-obs', payload: { type: 'reception', ...marsPayload } }, lookup);

  // Whoever asks — Earth's own software, Mars's own software, or a
  // third party entirely — recomputing from the identical real
  // evidence gives the identical real, comparable coordinate for the
  // shared target. Neither Earth's nor Mars's own, unrelated local
  // progression enters into it at all.
  const result = await computeCausalTick(mirrorState, identityCostState, [targetEvent], 'shared-target');
  assert.equal(result.tick, 42);
  assert.equal(result.totalWeight, 17000);
  assert.equal(result.observationCount, 2);
});
