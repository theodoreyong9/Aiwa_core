// Triangulation of a domain's position: what observers can PROVE about it, with no weight.
//
// A Mirror reception commitment does not carry an opinion, it carries a REFERENCE: "I received this event
// of X". The reference resolves, in the DAG, to the progression event that fixes its epoch — an event only
// X's key can sign. So an observation is a PROOF that X got at least that far, not a vote on where X is.
// Three consequences, none of which needs a weight:
//
//  - lowerBound: the highest epoch of X that any observer provably received. One honest observer is
//    enough to establish it; any number of observers who saw less cannot lower it, and nobody can raise
//    it — only X produces new evidence about X.
//  - contradiction: if X reports an epoch BELOW that bound, X contradicts its own signed history. The
//    evidence is the witnessing event, checkable by anyone.
//  - fork: two progression events of X held by observers, neither an ancestor of the other, are two
//    histories of X from one identity (a progression must chain to the last accepted one). Also provable.
//
// Every progression event it relies on is re-checked (`isAuthentic`, by default the signature check of
// progression.js: signed by the key whose id is the domain). An event that fails is dropped and reported in
// `rejected` — this is what closes the hole an earlier version of this file had, where an event attributed
// to X but forged by someone else, admitted by a log that did not check, raised the bound for free.
//
// What it cannot do — stated rather than hidden:
//  - It gives no UPPER bound. A domain that progressed offline is legitimately ahead of everything any
//    observer saw; `ahead` reports how far, and does not call it wrong.
//  - It is only as fresh as the freshest observer who really received something. Observers can carry
//    evidence or withhold it; they cannot forge it.
//  - It says nothing about whether observers are distinct actors. `observers` counts distinct identities and
//    is informational only — a coalition inflates it for free. Independence is a separate question.
//  - By default it checks the signature on the progression event, not its sequential (VDF) proof; the
//    chain check (replayProgression) does both, and assessPosition uses it whenever the reader holds the
//    domain's history from epoch 1.
//
// Status: EXPERIMENTAL. Exercised on the synthetic worlds of experiments/triangulation-scenarios.mjs, not on
// real networks.

import { verifyProgressionAuthorization, applyProgressionEvent, initialProgressionState } from './progression.js';

const ANCESTRY_BOUND = 10000;

/** The default authenticity check: the progression event is signed by the key whose id is its domain. */
export const signatureAuthentic = (event) => verifyProgressionAuthorization(event.payload);
const defaultIsAuthentic = signatureAuthentic;

const isProgressionOf = (event, domain) =>
  event?.payload?.type === 'progression' && event.payload.domain === domain && Number.isInteger(event.payload.epoch);

// The progression event that fixes the epoch a cited event stands for: itself, or its highest-epoch
// progression ancestor of the same domain. null when it resolves to none (proves nothing).
function resolveProgression(byId, domain, eventId) {
  const cited = byId.get(eventId);
  if (!cited || cited.payload?.domain !== domain) return null;
  if (isProgressionOf(cited, domain)) return cited;
  let best = null;
  const seen = new Set();
  const queue = [...cited.parents];
  while (queue.length > 0 && seen.size < ANCESTRY_BOUND) {
    const id = queue.shift();
    if (seen.has(id)) continue;
    seen.add(id);
    const event = byId.get(id);
    if (!event) continue;
    if (isProgressionOf(event, domain) && (best === null || event.payload.epoch > best.payload.epoch)) best = event;
    queue.push(...event.parents);
  }
  return best;
}

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
 * Replays `domain`'s progression events through the real reducer (applyProgressionEvent: epoch + 1, chained to the
 * last accepted transition, signed by the domain's key, sequential proof verified) and says which were ACCEPTED.
 * An event that only carries a genuine signature — e.g. one the domain signed itself, far ahead, with no
 * sequential work — is rejected here, as it is by anyone who verifies.
 * `genesis` is true when the reader holds the chain from epoch 1: without it nothing can be chained, so nothing
 * would be accepted, and the caller should not read that as "everything is forged".
 * @param {Array<{ id: string, parents: string[], payload: object }>} orderedEvents in topological order
 * @returns {Promise<{ accepted: Set<string>, genesis: boolean, rejections: object[] }>}
 */
export async function replayProgression(orderedEvents, domain, verifyFn) {
  let state = initialProgressionState();
  const accepted = new Set();
  let genesis = false;
  for (const event of orderedEvents) {
    if (!isProgressionOf(event, domain)) continue;
    if (event.payload.epoch === 1) genesis = true;
    const before = state.rejections.length;
    state = await applyProgressionEvent(state, event, verifyFn);
    if (state.rejections.length === before) accepted.add(event.id);
  }
  return { accepted, genesis, rejections: state.rejections };
}

/**
 * The events with every progression event of `domain` that fails `isAuthentic` removed.
 * @returns {Promise<{ events: object[], rejected: string[] }>}
 */
export async function authenticEvents(orderedEvents, domain, isAuthentic = defaultIsAuthentic) {
  const events = [];
  const rejected = [];
  for (const event of orderedEvents) {
    if (isProgressionOf(event, domain) && !(await isAuthentic(event))) rejected.push(event.id);
    else events.push(event);
  }
  return { events, rejected };
}

/**
 * @param {{ commitments: Record<string, Array<{ receivedFrom: Array<{ sourceDomain: string, eventId: string }> }>> }} mirrorState
 * @param {Array<{ id: string, parents: string[], payload: object }>} orderedEvents
 * @param {string} targetDomain
 * @param {{ isAuthentic?: (progressionEvent: object) => boolean | Promise<boolean> }} [options]
 * @returns {Promise<{ lowerBound: number, witnesses: object[], views: object[], observers: number, forks: Array<{ a: string, b: string }>, rejected: string[] } | null>}
 *   null when no observer has provably received anything of the target.
 */
export async function triangulate(mirrorState, orderedEvents, targetDomain, { isAuthentic = defaultIsAuthentic } = {}) {
  const byId = new Map(orderedEvents.map((event) => [event.id, event]));
  const verdicts = new Map(); // progression event id -> authentic?
  const authentic = async (event) => {
    if (!verdicts.has(event.id)) verdicts.set(event.id, Boolean(await isAuthentic(event)));
    return verdicts.get(event.id);
  };
  const rejected = new Set();
  const views = [];
  for (const [observer, commitments] of Object.entries(mirrorState.commitments)) {
    if (observer === targetDomain) continue; // a domain corroborating itself is not external evidence
    const cited = new Set();
    for (const commitment of commitments) {
      for (const ref of commitment.receivedFrom) if (ref.sourceDomain === targetDomain) cited.add(ref.eventId);
    }
    for (const eventId of cited) {
      const progression = resolveProgression(byId, targetDomain, eventId);
      if (progression === null) continue; // resolves to nothing: proves nothing
      if (!(await authentic(progression))) { rejected.add(progression.id); continue; }
      views.push({ observer, eventId: progression.id, epoch: progression.payload.epoch });
    }
  }
  if (views.length === 0) return null;

  const lowerBound = Math.max(...views.map((view) => view.epoch));
  const witnesses = views.filter((view) => view.epoch === lowerBound);

  const progressions = [...new Set(views.map((view) => view.eventId))];
  const forks = [];
  for (let i = 0; i < progressions.length; i++) {
    for (let j = i + 1; j < progressions.length; j++) {
      const a = progressions[i];
      const b = progressions[j];
      if (!isAncestor(byId, a, b) && !isAncestor(byId, b, a)) forks.push({ a, b });
    }
  }
  return { lowerBound, witnesses, views, observers: new Set(views.map((view) => view.observer)).size, forks, rejected: [...rejected] };
}

/**
 * What the proofs say about the epoch a domain reports for itself.
 * contradicted: it reports less than an observer provably received (its own signed history says otherwise).
 * forked: observers hold two unrelated histories of it (`forks` may come from a separate, signature-level pass).
 * ahead: how far it reports beyond the best proof — normal for offline progress, so never an accusation.
 * @returns {{ contradicted: boolean, forked: boolean, ahead: number | null, lowerBound: number | null, witnesses: object[], forks: object[] }}
 */
export function judgeSelfReport(selfReportedEpoch, triangulation, forks = triangulation ? triangulation.forks : []) {
  if (!triangulation) return { contradicted: false, forked: forks.length > 0, ahead: null, lowerBound: null, witnesses: [], forks };
  const { lowerBound, witnesses } = triangulation;
  return {
    contradicted: selfReportedEpoch < lowerBound,
    forked: forks.length > 0,
    ahead: Math.max(0, selfReportedEpoch - lowerBound),
    lowerBound,
    witnesses,
    forks,
  };
}
