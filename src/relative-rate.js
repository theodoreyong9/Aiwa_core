// A domain's own real, VDF-verified progression epoch (progression.js)
// is already an unfakeable marker of how much real, sequential work
// it has genuinely done — the exact same security property the whole
// system already relies on everywhere else. This file uses that
// existing marker for something new: a real, signed statement of
// "at MY OWN epoch X, I observed target domain Y at their epoch Z" —
// never a clock reading, never a timestamp, never anything measuring
// or declaring real elapsed time in any unit. Two such real,
// successive statements from the SAME observer about the SAME
// target let anyone compute a REAL, purely structural ratio — no
// clock consulted anywhere, by any party, at any point.
//
// This is deliberately kept fully separate from mirror.js's own real
// reception commitments — it never touches that already-tested
// structure, and is itself purely informational: it never gates,
// corrects, or bounds anything a domain can claim (matching
// causal-tick.js's own established principle).

import { ed25519 } from '@noble/curves/ed25519.js';
import { weightedMedian } from './weighted-median.js';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function canonicalWitnessMessage({ observer, observerEpoch, target, targetEpoch, sourceEventId }) {
  return JSON.stringify({ observer, observerEpoch, target, targetEpoch, sourceEventId });
}

/**
 * A real, signed statement: "at my own real, VDF-verified progression
 * epoch `observerEpoch`, I observed real target domain `target` at
 * their own real epoch `targetEpoch`, via real event `sourceEventId`."
 * Both epochs are real, already-verified quantities (progression.js);
 * nothing here is a clock reading of any kind.
 */
export async function buildRateWitness(keypair, observer, observerEpoch, target, targetEpoch, sourceEventId) {
  const fields = { observer, observerEpoch, target, targetEpoch, sourceEventId };
  const message = new TextEncoder().encode(canonicalWitnessMessage(fields));
  const signature = ed25519.sign(message, keypair.secretKey.slice(0, 32));
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(keypair.publicKey.toBytes()) };
}

/**
 * @returns {boolean} true only if the real signature verifies over
 * the exact real fields claimed — never trusted from the witness's
 * own claims about itself.
 */
export function verifyRateWitness(witness) {
  try {
    const { observer, observerEpoch, target, targetEpoch, sourceEventId, signature, signerPubkey } = witness;
    const message = new TextEncoder().encode(canonicalWitnessMessage({ observer, observerEpoch, target, targetEpoch, sourceEventId }));
    return ed25519.verify(hexToBytes(signature), message, hexToBytes(signerPubkey));
  } catch {
    return false;
  }
}

/**
 * From two real, successive, valid witnesses by the SAME real
 * observer about the SAME real target — the ratio of how much the
 * target's own real epoch advanced versus how much the observer's
 * own real epoch advanced, between these two real observations.
 * Purely structural: no clock, no timestamp, no declared duration of
 * any kind enters this computation anywhere.
 *
 * @returns {number|null} null if the pair is invalid (wrong order,
 * zero observer delta, mismatched observer/target, bad signature) —
 * a real, honest refusal to compute, never a fabricated ratio.
 */
export function computeRelativeRate(witnessEarlier, witnessLater) {
  if (!verifyRateWitness(witnessEarlier) || !verifyRateWitness(witnessLater)) return null;
  if (witnessEarlier.observer !== witnessLater.observer) return null;
  if (witnessEarlier.target !== witnessLater.target) return null;
  if (witnessEarlier.signerPubkey !== witnessLater.signerPubkey) return null;
  const observerDelta = witnessLater.observerEpoch - witnessEarlier.observerEpoch;
  if (!(observerDelta > 0)) return null; // must be real, later, forward progress — never zero or negative
  const targetDelta = witnessLater.targetEpoch - witnessEarlier.targetEpoch;
  if (targetDelta < 0) return null; // Mirror's own reception monotonicity — a real regression is never trusted
  return targetDelta / observerDelta;
}

/**
 * Aggregates many real (observer, target) relative-rate pairs into a
 * single, robust, informational estimate — weighted by each real
 * observer's own already-verified committed capital (identity-cost.js),
 * the identical real security shape causal-tick.js already relies on:
 * robust while adversarial weight stays below half of the total real
 * weight contributing an estimate. Purely informational — this NEVER
 * feeds back into what any domain can claim or how fast it may
 * progress; see causal-tick.js's own header for why that direction is
 * refused.
 *
 * @param {Array<{ratio: number, observerDomain: string}>} estimates
 * @param {ReturnType<typeof import('./identity-cost.js').initialIdentityCostState>} identityCostState
 * @returns {{ emergentRate: number, observationCount: number, totalWeight: number } | null}
 */
export function computeEmergentRate(estimates, identityCostState) {
  const weighted = [];
  let totalWeight = 0;
  for (const { ratio, observerDomain } of estimates) {
    const weight = identityCostState.registered[observerDomain]?.burnedLamports ?? 0;
    if (!(weight > 0)) continue; // no real committed capital — no real weight, exactly like causal-tick.js
    if (!(ratio > 0) || !Number.isFinite(ratio)) continue;
    weighted.push({ value: ratio, weight });
    totalWeight += weight;
  }
  if (weighted.length === 0) return null; // bottom: insufficiently determined, a real honest absence
  return { emergentRate: weightedMedian(weighted), observationCount: weighted.length, totalWeight };
}

// Composing ρ_AB · ρ_BC = ρ_AC is mathematically valid, but real and
// dangerous if built without a bound: A→B was measured at some real
// point, B→C at some real, possibly much later point, and if B's own
// real relative rate drifted between the two (genuinely — new
// hardware, thermal throttling, different load — never requiring any
// forged signature), the composed result can be badly wrong. This
// bounds that risk using B's own already-verified progression epoch
// as the freshness measure — never a clock, never a timestamp — but
// it is a real mitigation, not a closure: even within the bound, the
// intermediate domain still freely chooses when it observes the next
// link, and genuine drift can in principle occur within any bound.
// Callers should treat a wide bound as real, reduced confidence, not
// as equivalent to a short, direct measurement.
export function composeRelativeRates(pairAB, pairBC, { maxFreshnessGap } = {}) {
  if (!(maxFreshnessGap > 0)) throw new Error('maxFreshnessGap must be a positive real epoch count — required, never defaulted silently, since the right bound is deployment-specific.');

  const rhoAB = computeRelativeRate(pairAB.earlier, pairAB.later);
  const rhoBC = computeRelativeRate(pairBC.earlier, pairBC.later);
  if (rhoAB === null || rhoBC === null) return null;

  // The chain must genuinely connect: A's own later witness about B
  // must reference the identical real domain B is observing itself as
  // in the B→C pair — never trusted from a caller's own claim that
  // they connect.
  if (pairAB.later.target !== pairBC.earlier.observer) return null;

  // B's own real epoch when it started observing C, minus B's own
  // real epoch as last referenced by A — both refer to the identical
  // real, verified quantity (B's own progression), never a clock.
  const freshnessGap = pairBC.earlier.observerEpoch - pairAB.later.targetEpoch;
  if (freshnessGap < 0) return null; // chronologically impossible for B's own real progression — refused, never silently reordered
  if (freshnessGap > maxFreshnessGap) return null; // too stale to trust composing through — a real, honest refusal, not a degraded guess

  return { composedRate: rhoAB * rhoBC, freshnessGap, rhoAB, rhoBC };
}
