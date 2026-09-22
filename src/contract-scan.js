// Generic, reusable scanning primitives for a contract's own events.
// Factored out after three separate contracts — generous-transfer.js,
// matching-contract.js, relative-rate.js — each wrote their own
// bespoke scan reimplementing one of the same two patterns below.
// Pure, no browser dependency, no knowledge of what any particular
// contract's events mean. Reducer-shaped events ({payload: {type,
// ...}}) — see adapt-event.js.

/**
 * Every id ever consumed as a parent of a 'progression' event — the
 * general shape behind "this offer/commitment has already been acted
 * on", for any contract whose own resolution rides on progression.
 * `domain`, if given, restricts to progression events for that one
 * domain. `only`, if given, restricts the result to ids that are
 * members of that set, so a caller checking a specific candidate set
 * (e.g. "which of MY sent offers") never has to filter out every
 * other domain's unrelated ids itself.
 */
export function collectProgressionParentIds(events, { domain, only } = {}) {
  const ids = new Set();
  for (const ev of events) {
    if (ev.payload?.type !== 'progression') continue;
    if (domain !== undefined && ev.payload?.domain !== domain) continue;
    for (const p of ev.parents) {
      if (only !== undefined && !only.has(p)) continue;
      ids.add(p);
    }
  }
  return ids;
}

/**
 * Real events matching `predicate`, grouped by `keyOf(ev)` into an
 * object of arrays, in the real order they appear in `events` — the
 * general shape behind "this contract's own events, indexed by which
 * other event they concern". `itemOf`, if given, transforms each
 * matched event before it is pushed (defaults to just its payload).
 */
export function groupEventsByKey(events, { predicate, keyOf, itemOf }) {
  const groups = {};
  for (const ev of events) {
    if (!predicate(ev)) continue;
    const key = keyOf(ev);
    if (key === undefined || key === null) continue;
    if (!groups[key]) groups[key] = [];
    groups[key].push(itemOf ? itemOf(ev) : ev.payload);
  }
  return groups;
}
