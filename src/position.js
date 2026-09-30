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
// What counts as evidence (`verifyChain`):
//   'auto' (default) — if the reader holds the target's history from epoch 1, its progression events are
//       REPLAYED through the real reducer and only the accepted ones count (signature, chain, sequential
//       proof: what anyone who verifies does); otherwise only the signature of each event is checked, and the
//       result says so (`verification: 'signature'`) — a partial log cannot be chained, and a reader in that
//       position is trusting more.
//   'require' — replay always; a reader without the genesis gets nothing accepted.
//   'off' — signature only.
// Both rules see the same, filtered events, so a fake far-ahead event — forged by someone else, or signed by
// the target itself without doing the work — moves neither, and observers whose only evidence was such an
// event contribute nothing. Forks are the exception, on purpose: a second lineage is rejected by the linear
// chain, and is exactly the evidence of one, so forks are read from the signed events.
//
// Status: EXPERIMENTAL — see experiments/triangulation-scenarios.mjs for what it was compared on, and for what
// it does not cover: independence of observers, freshness beyond the freshest honest observer, and colluders
// when the reader cannot replay the chain.

import { computeCausalTick, checkCausalConsistency } from './causal-tick.js';
import { authenticEvents, replayProgression, signatureAuthentic, triangulate, judgeSelfReport } from './triangulation.js';

/**
 * @param {object} args
 * @param {object} args.mirrorState
 * @param {object} args.identityCostState
 * @param {Array<{ id: string, parents: string[], payload: object }>} args.orderedEvents in topological order
 * @param {string} args.targetDomain
 * @param {number | null} [args.selfReportedEpoch] the epoch the domain itself reports, if any
 * @param {number} [args.tolerance] only for the informational `estimateConsistent`
 * @param {object} [args.hardwareAttestations] passed through to computeCausalTick
 * @param {'auto' | 'require' | 'off'} [args.verifyChain]
 * @param {Function} [args.verifyFn] the sequential-proof verifier (defaults to progression.js's)
 */
export async function assessPosition({ mirrorState, identityCostState, orderedEvents, targetDomain, selfReportedEpoch = null, tolerance = 5, hardwareAttestations = {}, verifyChain = 'auto', verifyFn }) {
  let verification = 'signature';
  let isAuthentic = signatureAuthentic;
  if (verifyChain !== 'off') {
    const replay = await replayProgression(orderedEvents, targetDomain, verifyFn);
    if (replay.genesis || verifyChain === 'require') {
      verification = 'chain';
      isAuthentic = async (event) => replay.accepted.has(event.id);
    }
  }
  const { events, rejected } = await authenticEvents(orderedEvents, targetDomain, isAuthentic);
  const trusted = async () => true;
  const proof = await triangulate(mirrorState, events, targetDomain, { isAuthentic: trusted });
  const estimate = await computeCausalTick(mirrorState, identityCostState, events, targetDomain, hardwareAttestations);

  // Forks come from the signed events: the linear chain rejects a second lineage, which is the evidence.
  const signed = verification === 'chain' ? (await authenticEvents(orderedEvents, targetDomain, signatureAuthentic)).events : events;
  const forks = (await triangulate(mirrorState, signed, targetDomain, { isAuthentic: trusted }))?.forks ?? [];

  const floor = proof ? proof.lowerBound : null;
  const position = estimate ? (floor === null ? estimate.tick : Math.max(estimate.tick, floor)) : floor;
  const judged = selfReportedEpoch === null ? null : judgeSelfReport(selfReportedEpoch, proof, forks);
  return {
    position,
    proof,
    forks,
    estimate,
    verification,
    staleEstimate: estimate !== null && floor !== null && estimate.tick < floor,
    rejectedEvents: rejected,
    accuse: judged ? judged.contradicted || judged.forked : false,
    contradicted: judged ? judged.contradicted : false,
    forked: judged ? judged.forked : forks.length > 0,
    ahead: judged ? judged.ahead : null,
    estimateConsistent: selfReportedEpoch === null || !estimate ? null : checkCausalConsistency(selfReportedEpoch, estimate, tolerance).consistent,
  };
}
