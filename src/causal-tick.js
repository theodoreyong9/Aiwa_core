// One real interface: Evidence -> Causal Tick, or an honest null when
// evidence is insufficient. "Local" and "cross-domain" are not two
// separate mechanisms — the identical function, given more evidence
// (a newly-imported domain's history, a newly-signed reception
// commitment), simply produces a more refined result.
//
// A domain's own progression epoch (progression.js) remains the real,
// unconditional source of truth for its own accrual — bound by a real
// VDF, secure even with zero external observers. This file adds a
// complementary view: what OTHER domains, weighted by their own real
// committed capital (identity-cost.js), corroborate about a domain's
// position.
//
// REPLAY GIVES ZERO ADDITIONAL INFLUENCE: each real observer
// contributes exactly ONE estimate, at their own most-recent,
// highest-resolving observation of the target domain — never one
// estimate per historical reference. An observer who commits the
// identical reception twice, or who has simply accumulated many old
// commitments over time, must never see their real weight counted
// more than once just by having said the same true thing more than
// once. This mirrors Mirror's own reception-monotonicity philosophy:
// only a domain's current, real state of knowledge matters.
//
// Hardware attestation (hardware-attestation.js) is fully OPTIONAL —
// this evidence interface works with software primitives alone. When
// present, it is reported as a SEPARATE, additional confidence signal
// (hardwareBackedWeight, hardwareBackedObservers) — it never gates
// participation, never scales weight, never becomes a required input.

import { deriveSourceEpochLookup } from './mirror.js';
import { weightedMedian } from './weighted-median.js';
import { isIndependenceAttested } from './hardware-attestation.js';

/**
 * @param {ReturnType<typeof import('./mirror.js').initialMirrorState>} mirrorState
 * @param {ReturnType<typeof import('./identity-cost.js').initialIdentityCostState>} identityCostState
 * @param {Array<{id: string, parents: string[], payload: any}>} orderedEvents
 * @param {string} targetDomain
 * @param {Record<string, Array<{issuance: object, binding: object}>>} [hardwareAttestations] optional, keyed by observer domain
 * @returns {Promise<{ tick: number, interval: [number, number], totalWeight: number, observationCount: number, hardwareBackedWeight: number, hardwareBackedObservers: number } | null>} null (bottom) if no real evidence exists yet
 */
export async function computeCausalTick(mirrorState, identityCostState, orderedEvents, targetDomain, hardwareAttestations = {}) {
  const sourceEpochLookup = deriveSourceEpochLookup(orderedEvents);
  const estimates = [];
  let totalWeight = 0;
  let hardwareBackedWeight = 0;
  let hardwareBackedObservers = 0;

  for (const [observerDomain, commitments] of Object.entries(mirrorState.commitments)) {
    if (observerDomain === targetDomain) continue; // a domain corroborating itself is not external evidence
    const weight = identityCostState.registered[observerDomain]?.burnedLamports ?? 0;
    if (!(weight > 0)) continue; // no real committed capital — no real weight

    // Real, current best knowledge only — the highest epoch this real
    // observer has validly resolved for the target, across every
    // commitment they've ever made. A real, single contribution, not
    // one per historical mention.
    let bestEpoch = null;
    for (const commitment of commitments) {
      for (const ref of commitment.receivedFrom) {
        if (ref.sourceDomain !== targetDomain) continue;
        const epoch = sourceEpochLookup(targetDomain, ref.eventId);
        if (epoch === null) continue; // a claimed reference that does not resolve to a real event — ignored, not trusted
        if (bestEpoch === null || epoch > bestEpoch) bestEpoch = epoch;
      }
    }

    if (bestEpoch !== null) {
      estimates.push({ value: bestEpoch, weight });
      totalWeight += weight;
      const attestations = hardwareAttestations[observerDomain];
      if (attestations && (await isIndependenceAttested(attestations, observerDomain))) {
        hardwareBackedWeight += weight;
        hardwareBackedObservers += 1;
      }
    }
  }

  if (estimates.length === 0) return null; // bottom: insufficiently determined

  const values = estimates.map((e) => e.value);
  return {
    tick: weightedMedian(estimates),
    interval: [Math.min(...values), Math.max(...values)],
    totalWeight,
    observationCount: estimates.length,
    hardwareBackedWeight,
    hardwareBackedObservers,
  };
}

/**
 * @param {number} selfReportedEpoch
 * @param {Awaited<ReturnType<typeof computeCausalTick>>} causalTick
 * @param {number} tolerance
 * @returns {{ consistent: boolean, gap: number | null }}
 */
export function checkCausalConsistency(selfReportedEpoch, causalTick, tolerance) {
  if (!causalTick) return { consistent: true, gap: null }; // no evidence yet — nothing to be inconsistent WITH
  const gap = Math.abs(selfReportedEpoch - causalTick.tick);
  return { consistent: gap <= tolerance, gap };
}
