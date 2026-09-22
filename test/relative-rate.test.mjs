import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '@aiwa/record';
import { initialIdentityCostState, registerIdentityCost } from '../src/identity-cost.js';
import { buildRateWitness, verifyRateWitness, computeRelativeRate, computeEmergentRate, composeRelativeRates } from '../src/relative-rate.js';

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { secretKey: new Uint8Array([...seed, ...pubkeyBytes]), publicKey: { toBytes: () => pubkeyBytes } };
}
function fundedIdentityCost(state, domain, lamports) {
  return registerIdentityCost(state, { domain, tx: { signature: `sig-${domain}-${Math.random()}`, err: null, incineratorBalanceDeltaLamports: lamports, commitment: 'finalized', slot: 1 } }).state;
}

test('a real witness verifies against its own real signature', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  assert.equal(verifyRateWitness(w), true);
});

test('SECURITY: a forged witness (tampered field after signing) is rejected', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  const tampered = { ...w, targetEpoch: 999999 };
  assert.equal(verifyRateWitness(tampered), false);
});

test('THE REAL PROPERTY, NO CLOCK: the ratio of two real, successive witnesses recovers the real relative rate exactly, with zero timestamps anywhere', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  // The target genuinely runs at 2x the observer's own real rate —
  // never declared anywhere, only ever visible through the real,
  // structural epoch deltas themselves.
  const w1 = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  const w2 = await buildRateWitness(signer, observer, 50, 'target', 180, 'e2');
  const ratio = computeRelativeRate(w1, w2);
  assert.equal(ratio, 2, '(180-100)/(50-10) = 2, recovered purely structurally');
});

test('a real 1:1 relative rate is recovered exactly when both really progress at the same pace', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w1 = await buildRateWitness(signer, observer, 5, 'target', 50, 'e1');
  const w2 = await buildRateWitness(signer, observer, 25, 'target', 70, 'e2');
  assert.equal(computeRelativeRate(w1, w2), 1);
});

test('SECURITY: witnesses out of real order (later epoch first) are rejected, never silently reordered', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w1 = await buildRateWitness(signer, observer, 50, 'target', 180, 'e2');
  const w2 = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  assert.equal(computeRelativeRate(w1, w2), null);
});

test('a zero observer delta (same real epoch twice) is refused, never a divide-by-zero fabrication', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w1 = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  const w2 = await buildRateWitness(signer, observer, 10, 'target', 120, 'e2');
  assert.equal(computeRelativeRate(w1, w2), null);
});

test('SECURITY: a target epoch that regresses between two real witnesses is refused — reception monotonicity', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w1 = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  const w2 = await buildRateWitness(signer, observer, 20, 'target', 90, 'e2');
  assert.equal(computeRelativeRate(w1, w2), null);
});

test('SECURITY: mismatched observers or targets between the two witnesses are refused', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const observerA = await deriveId(signerA.publicKey.toBytes());
  const observerB = await deriveId(signerB.publicKey.toBytes());
  const w1 = await buildRateWitness(signerA, observerA, 10, 'target', 100, 'e1');
  const w2 = await buildRateWitness(signerB, observerB, 50, 'target', 180, 'e2');
  assert.equal(computeRelativeRate(w1, w2), null);
});

test('THE FULL EXPERIMENT: ten real, independently-speeded domains — the emergent, weighted-median rate recovers a real, meaningful central value, computed with zero clocks anywhere, ever', async () => {
  // Ten real domains, each really running at a different real relative
  // speed compared to one fixed real reference observer — the exact
  // scenario mathematically verified by hand before writing this file.
  const realSpeedRatios = [0.4, 0.6, 0.8, 1.0, 1.0, 1.1, 1.3, 1.5, 2.0, 2.5];
  let identityCostState = initialIdentityCostState();
  const estimates = [];

  for (let i = 0; i < realSpeedRatios.length; i++) {
    const signer = makeSigner();
    const observer = await deriveId(signer.publicKey.toBytes());
    identityCostState = fundedIdentityCost(identityCostState, observer, 1000);
    const observerEpochStart = 10, observerEpochEnd = 50; // the observer's own real progression, identical for all ten here
    const targetEpochStart = 100;
    const targetEpochEnd = targetEpochStart + Math.round((observerEpochEnd - observerEpochStart) * realSpeedRatios[i]);
    const w1 = await buildRateWitness(signer, observer, observerEpochStart, 'shared-target', targetEpochStart, 'e1');
    const w2 = await buildRateWitness(signer, observer, observerEpochEnd, 'shared-target', targetEpochEnd, 'e2');
    const ratio = computeRelativeRate(w1, w2);
    estimates.push({ ratio, observerDomain: observer });
  }

  const result = computeEmergentRate(estimates, identityCostState);
  assert.equal(result.observationCount, 10);
  // weighted-median.js's own real, defined behavior for equal weights
  // is the cumulative-weight crossing point, not an average of the two
  // middle values — 1.0 here, the real value at the 50%-weight mark
  // among [0.4,0.6,0.8,1.0,1.0,1.1,1.3,1.5,2.0,2.5].
  assert.equal(result.emergentRate, 1, 'a real, meaningful central value, recovered with zero clocks, zero timestamps, matching weighted-median.js\'s own already-defined behavior');
});

test('SECURITY: an observer with zero real committed capital contributes zero weight to the emergent rate', async () => {
  const signer = makeSigner();
  const observer = await deriveId(signer.publicKey.toBytes());
  const w1 = await buildRateWitness(signer, observer, 10, 'target', 100, 'e1');
  const w2 = await buildRateWitness(signer, observer, 50, 'target', 500, 'e2'); // a wildly fabricated ratio
  const ratio = computeRelativeRate(w1, w2);
  const result = computeEmergentRate([{ ratio, observerDomain: observer }], initialIdentityCostState());
  assert.equal(result, null, 'zero real committed capital must mean zero real influence, exactly like causal-tick.js');
});

test('SECURITY: real majority weight resists a funded but minority adversary reporting a fabricated rate', async () => {
  let identityCostState = initialIdentityCostState();
  const estimates = [];
  for (let i = 0; i < 3; i++) {
    const signer = makeSigner();
    const observer = await deriveId(signer.publicKey.toBytes());
    identityCostState = fundedIdentityCost(identityCostState, observer, 50000);
    const w1 = await buildRateWitness(signer, observer, 0, 'target', 0, 'e1');
    const w2 = await buildRateWitness(signer, observer, 100, 'target', 100, 'e2'); // real 1:1 rate
    estimates.push({ ratio: computeRelativeRate(w1, w2), observerDomain: observer });
  }
  const attacker = makeSigner();
  const attackerDomain = await deriveId(attacker.publicKey.toBytes());
  identityCostState = fundedIdentityCost(identityCostState, attackerDomain, 1000);
  const aw1 = await buildRateWitness(attacker, attackerDomain, 0, 'target', 0, 'e1');
  const aw2 = await buildRateWitness(attacker, attackerDomain, 100, 'target', 999999, 'e2'); // a real, fabricated extreme ratio
  estimates.push({ ratio: computeRelativeRate(aw1, aw2), observerDomain: attackerDomain });

  const result = computeEmergentRate(estimates, identityCostState);
  assert.equal(result.emergentRate, 1, 'real majority weight must dominate, the fabricated minority must not move the emergent rate');
});

test('THE REAL COMPOSITION PROPERTY: composing through a real, honest, unchanged intermediate domain gives the exact real result', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());

  // A observes B: real 1:1 rate.
  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLater = await buildRateWitness(signerA, domainA, 100, domainB, 100, 'e2');

  // B observes C (real 1.5x rate), starting RIGHT after A's last real reference to B — a small, real freshness gap.
  const bcEarlier = await buildRateWitness(signerB, domainB, 105, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(signerB, domainB, 205, 'domain-c', 150, 'e4');

  const result = composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 50 });
  assert.equal(result.composedRate, 1.5, 'ρ_AB(1) × ρ_BC(1.5) = 1.5, exact, with a real, small, honest freshness gap');
  assert.equal(result.freshnessGap, 5);
});

test('THE REAL VULNERABILITY, VERIFIED AND NOW BOUNDED: a large freshness gap where the intermediate domain has genuinely drifted is refused, not silently composed into a wrong result', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());

  // A observes B early: real 1:1 rate, at B's own epoch 100.
  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLater = await buildRateWitness(signerA, domainA, 100, domainB, 100, 'e2');

  // MUCH LATER — B's own epoch 10000 — B (now genuinely running 2x
  // faster, real new hardware, nothing forged) observes C at 1.5x ITS
  // OWN current rate. A real, large, honest freshness gap.
  const bcEarlier = await buildRateWitness(signerB, domainB, 10000, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(signerB, domainB, 10100, 'domain-c', 150, 'e4');

  const refused = composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 50 });
  assert.equal(refused, null, 'a real, large freshness gap must be refused outright — never silently composed into a misleading result');

  // The SAME pair, with a bound wide enough to allow it, DOES produce
  // the real, exact composed number this scenario's own math predicts
  // — confirming the refusal above was the freshness gate, not some
  // other bug, and demonstrating concretely why a wide bound is real,
  // reduced confidence, not equivalent to a short one.
  const allowed = composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 10000 });
  assert.equal(allowed.composedRate, 1.5, 'the real math ρ_AB(1) × ρ_BC(1.5) = 1.5 — a real number, but one this test\'s own default bound correctly refuses to trust');
});

test('SECURITY: a composition whose two links do not genuinely reference the same real intermediate domain is refused', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());

  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLater = await buildRateWitness(signerA, domainA, 100, domainB, 100, 'e2');
  // The second pair's own observer is a DIFFERENT real domain than the one A actually observed.
  const impostor = makeSigner();
  const impostorDomain = await deriveId(impostor.publicKey.toBytes());
  const bcEarlier = await buildRateWitness(impostor, impostorDomain, 105, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(impostor, impostorDomain, 205, 'domain-c', 150, 'e4');

  const result = composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 50 });
  assert.equal(result, null, 'the chain must genuinely connect through the identical real domain — never trusted from a caller\'s own claim');
});

test('SECURITY: a negative (chronologically impossible) freshness gap is refused', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());

  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLater = await buildRateWitness(signerA, domainA, 100, domainB, 100, 'e2');
  // B's own witness about C claims to start BEFORE A's own last real reference to B's epoch.
  const bcEarlier = await buildRateWitness(signerB, domainB, 50, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(signerB, domainB, 150, 'domain-c', 150, 'e4');

  const result = composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 200 });
  assert.equal(result, null, 'a chronologically impossible gap for B\'s own real progression must be refused, never silently reordered');
});

test('maxFreshnessGap is required, never silently defaulted — the right bound is deployment-specific', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());
  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLater = await buildRateWitness(signerA, domainA, 100, domainB, 100, 'e2');
  const bcEarlier = await buildRateWitness(signerB, domainB, 105, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(signerB, domainB, 205, 'domain-c', 150, 'e4');

  assert.throws(() => composeRelativeRates({ earlier: abEarlier, later: abLater }, { earlier: bcEarlier, later: bcLater }, {}), /maxFreshnessGap/);
});

test('composeRelativeRates returns null (never throws) if either underlying pair is itself invalid', async () => {
  const signerA = makeSigner();
  const signerB = makeSigner();
  const domainA = await deriveId(signerA.publicKey.toBytes());
  const domainB = await deriveId(signerB.publicKey.toBytes());
  const abEarlier = await buildRateWitness(signerA, domainA, 0, domainB, 0, 'e1');
  const abLaterBad = await buildRateWitness(signerA, domainA, 0, domainB, 100, 'e2'); // zero observer delta — invalid on its own
  const bcEarlier = await buildRateWitness(signerB, domainB, 105, 'domain-c', 0, 'e3');
  const bcLater = await buildRateWitness(signerB, domainB, 205, 'domain-c', 150, 'e4');

  const result = composeRelativeRates({ earlier: abEarlier, later: abLaterBad }, { earlier: bcEarlier, later: bcLater }, { maxFreshnessGap: 50 });
  assert.equal(result, null);
});
