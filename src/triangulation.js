// Triangulation of a domain's position — PROTOTYPE. Not wired into computeCausalTick, not exported
// from index.js: it exists to be compared with the weighted median (experiments/), and to see whether
// the same question can be answered without any weight.
//
// The idea. A reception commitment does not carry an opinion, it carries a REFERENCE: "I received this
// event of X". The reference resolves, in the DAG, to a real event that only X could have produced
// (its signature; its epoch bound by X's own sequential proof). So an observation is a PROOF that X got
// at least that far, not a vote on where X is. Three consequences, none of which needs a weight:
//
//  - lowerBound: the highest epoch of X that any observer provably received. One honest observer is
//    enough to establish it; any number of observers who saw less cannot lower it, and nobody can raise
//    it — only X produces new evidence about X. (A median, by contrast, can be dragged down by enough
//    observers who merely saw an old state.)
//  - contradiction: if X reports an epoch BELOW that bound, X contradicts its own signed history.
//    The evidence is the witnessing event, checkable by anyone.
//  - fork: two events of X, cited by observers, neither an ancestor of the other, are two histories of
//    X from one identity. Also provable, and also weight-free.
//
// What it cannot do — stated rather than hidden:
//  - It gives no UPPER bound. A domain that progressed offline is legitimately ahead of everything any
//    observer saw; `ahead` reports how far, and does not call it wrong.
//  - It is only as fresh as the freshest observer who really received something. Observers can carry
//    evidence or withhold it; they cannot forge it.
//  - It says nothing about whether the observers are distinct actors. `observers` counts distinct
//    identities and is informational only — a coalition inflates it for free. Independence (hardware
//    roots, or something else) is a separate question this file does not answer.
//  - Fork detection assumes the events it is given were verified as X's own when they entered the
//    log (EventLog.append does); it does not re-verify signatures.

import { deriveSourceEpochLookup } from './mirror.js';

const ANCESTRY_BOUND = 10000;

function isAncestor(byId, ancestorId, descendantId) {
  if (ancestorId === descendantId) return true;
  const seen = new Set();
  const queue = [...(byId.get(descendantId)?.parents ?? [])];
  while (queue.length > 0 && seen.size < ANCESTRY_BOUND) {
    const id = queue.shift();
    if (id === ancestorId) return true;
    if (seen.has(id)) continue;
    seen.add(id);
    const event = byId.get(id);
    if (event) queue.push(...event.parents);
  }
  return false;
}

/**
 * @param {{ commitments: Record<string, Array<{ receivedFrom: Array<{ sourceDomain: string, eventId: string }> }>> }} mirrorState
 * @param {Array<{ id: string, parents: string[], payload: object }>} orderedEvents
 * @param {string} targetDomain
 * @returns {{ lowerBound: number, witnesses: Array<{ observer: string, eventId: string, epoch: number }>, views: Array<{ observer: string, eventId: string, epoch: number }>, observers: number, forks: Array<{ a: string, b: string }> } | null}
 *   null when no observer has provably received anything of the target.
 */
export function triangulate(mirrorState, orderedEvents, targetDomain) {
  const byId = new Map(orderedEvents.map((event) => [event.id, event]));
  const lookup = deriveSourceEpochLookup(orderedEvents);
  const views = [];
  for (const [observer, commitments] of Object.entries(mirrorState.commitments)) {
    if (observer === targetDomain) continue; // a domain corroborating itself is not external evidence
    const cited = new Map();
    for (const commitment of commitments) {
      for (const ref of commitment.receivedFrom) {
        if (ref.sourceDomain !== targetDomain) continue;
        const epoch = lookup(targetDomain, ref.eventId);
        if (epoch === null || epoch === undefined) continue; // a reference that resolves to nothing proves nothing
        cited.set(ref.eventId, epoch);
      }
    }
    for (const [eventId, epoch] of cited) views.push({ observer, eventId, epoch });
  }
  if (views.length === 0) return null;

  const lowerBound = Math.max(...views.map((view) => view.epoch));
  const witnesses = views.filter((view) => view.epoch === lowerBound);

  const citedEvents = [...new Set(views.map((view) => view.eventId))];
  const forks = [];
  for (let i = 0; i < citedEvents.length; i++) {
    for (let j = i + 1; j < citedEvents.length; j++) {
      const a = citedEvents[i];
      const b = citedEvents[j];
      if (!isAncestor(byId, a, b) && !isAncestor(byId, b, a)) forks.push({ a, b });
    }
  }
  return { lowerBound, witnesses, views, observers: new Set(views.map((view) => view.observer)).size, forks };
}

/**
 * What the triangulation says about the epoch a domain reports for itself.
 * contradicted: it reports less than an observer provably received (its own signed history says otherwise).
 * forked: observers hold two unrelated histories of it.
 * ahead: how far it reports beyond the best proof — normal for offline progress, so never an accusation.
 * @returns {{ contradicted: boolean, forked: boolean, ahead: number | null, lowerBound: number | null, witnesses: object[], forks: object[] }}
 */
export function judgeSelfReport(selfReportedEpoch, triangulation) {
  if (!triangulation) return { contradicted: false, forked: false, ahead: null, lowerBound: null, witnesses: [], forks: [] };
  const { lowerBound, witnesses, forks } = triangulation;
  return {
    contradicted: selfReportedEpoch < lowerBound,
    forked: forks.length > 0,
    ahead: Math.max(0, selfReportedEpoch - lowerBound),
    lowerBound,
    witnesses,
    forks,
  };
}
