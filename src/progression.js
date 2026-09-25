// A domain's own progression epoch advances only through a valid
// transition: monotonic (+1 exactly), causally chained to the domain's
// last accepted transition, and carrying a real sequential VDF proof
// (see vdf.js) — bounding the RATE of advancement, not calendar time.
//
// Events here use this package's own internal convention: {id,
// parents, payload}, with payload.type — see adapt-event.js for the
// bridge from event.js's own wire event shape.

import { vdfSeed, verifyVdfChain } from './vdf.js';

export function initialProgressionState() {
  return { domains: {}, rejections: [] };
}

/**
 * The real parent set a NEW progression event for a domain must declare.
 *
 * applyProgressionEvent's own causal-chain check below requires the
 * domain's last accepted progression event id to be a DIRECT parent —
 * not just a transitive ancestor. `heads` (a log's own current heads,
 * the parents every other real event builder in this codebase uses)
 * only satisfies that for free when nothing else was published for
 * this domain since the last progression tick. The moment any other
 * event (an accrual, a claim, a checkpoint...) becomes the sole head in
 * between — a completely ordinary sequence, e.g. recordCommitment()
 * right before advanceProgress() — `heads` alone silently drops the
 * chain, and every progression event from then on is permanently
 * rejected as "not chained", since the reducer's own lastId can then
 * never again match a real parent.
 *
 * Real fix, not a verification workaround: a progression event
 * genuinely does have two real causal dependencies — the log's current
 * tip, AND its own type's last accepted transition — so it should
 * honestly declare both as parents (a real merge, not a forced choice).
 * Any real progression-event builder should route its parents through
 * this, rather than reimplementing the same rule.
 */
export function progressionParents(heads, lastId) {
  return lastId && !heads.includes(lastId) ? [...heads, lastId] : heads;
}

// verifyFn defaults to the real, main-thread verifyVdfChain — every
// existing call site, and this project's own Node-based test suite,
// keeps working unchanged. A caller with access to a real worker
// thread (catching up on a real, possibly large backlog) can inject a
// worker-backed verifier instead, so that even this one-time catch-up
// work never has to run on the same thread that also needs to render
// and handle input.
export async function applyProgressionEvent(state, event, verifyFn = verifyVdfChain) {
  verifyFn ??= verifyVdfChain;
  const payload = event.payload;
  if (!payload || payload.type !== 'progression') return state;

  const { domain, epoch, vdfIterations, vdfOutput } = payload;
  const reject = (reason) => ({
    ...state,
    rejections: [...state.rejections, { eventId: event.id, domain, reason }],
  });

  if (typeof domain !== 'string' || domain.length === 0) return reject('missing domain');
  if (!Number.isInteger(epoch) || epoch < 1) return reject('epoch must be a positive integer');

  const current = state.domains[domain] ?? { epoch: 0, lastId: null, vdfOutput: null };

  if (epoch !== current.epoch + 1) return reject(`expected epoch ${current.epoch + 1}, got ${epoch}`);
  if (current.lastId !== null && !event.parents.includes(current.lastId)) {
    return reject(`does not chain from this domain's last accepted transition ${current.lastId}`);
  }
  if (!Number.isInteger(vdfIterations) || vdfIterations < 1) return reject('vdfIterations must be a positive integer');

  const seed = vdfSeed(domain, current.vdfOutput ?? 'genesis');
  if (!(await verifyFn(seed, vdfIterations, vdfOutput))) {
    return reject('VDF proof does not verify against the recomputed chain');
  }

  return { ...state, domains: { ...state.domains, [domain]: { epoch, lastId: event.id, vdfOutput } } };
}

export async function materializeProgression(orderedEvents, verifyFn = verifyVdfChain) {
  verifyFn ??= verifyVdfChain;
  let state = initialProgressionState();
  for (const event of orderedEvents) state = await applyProgressionEvent(state, event, verifyFn);
  return state;
}
