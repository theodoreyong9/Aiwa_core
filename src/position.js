// A domain's position, from BOTH kinds of evidence, each used for what it is good at.
//
//  - Proofs (triangulation.js): what observers provably received. They set a floor, and they alone may
//    ACCUSE — a rewind or a fork — because the evidence of an accusation is an event anyone can check.
//  - The weighted median (causal-tick.js): where observers' committed capital says the domain is. It is an
//    estimate, never an accusation: enough weight on an old view moves it, and "far from the median" cannot
//    tell inflation from legitimate offline progress.
//
//   position  = max(median, proven lower bound) — the vote is never reported below what is proven;
//               with no funded observer at all, the proven bound alone.
//   accuse    = contradicted || forked — from proofs only.
//
// Both rules see the same events: every progression event of the target that fails the authenticity check is
// removed first (see triangulation.js), so a forged event cannot move either of them. Observers whose only
// evidence was forged simply contribute nothing.
//
// Status: EXPERIMENTAL — see experiments/triangulation-scenarios.mjs for what it was compared on, and for what
// it does not cover: independence of observers, and freshness beyond the freshest honest observer.

import { computeCausalTick, checkCausalConsistency } from './causal-tick.js';
import { authenticEvents, triangulate, judgeSelfReport } from './triangulation.js';

/**
 * @param {object} args
 * @param {object} args.mirrorState
 * @param {object} args.identityCostState
 * @param {Array<{ id: string, parents: string[], payload: object }>} args.orderedEvents
 * @param {string} args.targetDomain
 * @param {number | null} [args.selfReportedEpoch] the epoch the domain itself reports, if any
 * @param {number} [args.tolerance] only for the informational `estimateConsistent`
 * @param {object} [args.hardwareAttestations] passed through to computeCausalTick
 * @param {(progressionEvent: object) => boolean | Promise<boolean>} [args.isAuthentic]
 */
export async function assessPosition({ mirrorState, identityCostState, orderedEvents, targetDomain, selfReportedEpoch = null, tolerance = 5, hardwareAttestations = {}, isAuthentic }) {
  const { events, rejected } = await authenticEvents(orderedEvents, targetDomain, isAuthentic);
  const proof = await triangulate(mirrorState, events, targetDomain, { isAuthentic: async () => true });
  const estimate = await computeCausalTick(mirrorState, identityCostState, events, targetDomain, hardwareAttestations);

  const floor = proof ? proof.lowerBound : null;
  const position = estimate ? (floor === null ? estimate.tick : Math.max(estimate.tick, floor)) : floor;
  const judged = selfReportedEpoch === null ? null : judgeSelfReport(selfReportedEpoch, proof);
  return {
    position,
    proof,
    estimate,
    staleEstimate: estimate !== null && floor !== null && estimate.tick < floor,
    rejectedEvents: rejected,
    accuse: judged ? judged.contradicted || judged.forked : false,
    contradicted: judged ? judged.contradicted : false,
    forked: judged ? judged.forked : false,
    ahead: judged ? judged.ahead : null,
    estimateConsistent: selfReportedEpoch === null || !estimate ? null : checkCausalConsistency(selfReportedEpoch, estimate, tolerance).consistent,
  };
}
