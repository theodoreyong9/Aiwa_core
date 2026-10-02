// The order in which a reader folds events into state — the same for every reader that holds the same events.
//
// A log is a graph, not a line: two events that do not know of each other (two branches) have no order of their own.
// Almost always that does not matter (a domain's progression and the transfers of two other domains do not touch). It
// matters when two events contradict each other — one claim spent twice, one voucher redeemed twice, one claim id
// taken by two domains: whichever is folded first wins and the other is refused. Folded in the order they happened to
// ARRIVE in, two readers holding exactly the same events could pick two different winners, and keep doing so.
//
// canonicalOrder removes that: among the events that can come next (all their parents already placed), the one with the
// smallest id goes first. It is a topological order (a parent always precedes its children), and given the same set of
// events it returns the same sequence whatever order they were handed in, or arrived in.
//
// What this is NOT: fairness. The winner of a conflict is the event with the smaller id — arbitrary, and a signer who
// writes two contradicting events can try variants until the one he wants has the smaller id. It makes readers AGREE; it
// does not make the winner the "first" one in time (nothing here has a clock) nor protect whoever accepted the other. The
// proof that the signer wrote both stays: two valid signatures on contradicting events.

/**
 * @param {Array<{ id: string, parents?: string[] }>} events duplicates (same id) are kept once
 * @param {{ placed?: Iterable<string> }} [options] `placed`: ids already folded before this batch (the caller's `excludeIds`).
 *   A parent that is neither in `events` nor in `placed` — pruned history, an ancestor the reader never had — counts as satisfied.
 * @returns {Array} the same events, in canonical order
 */
export function canonicalOrder(events, { placed } = {}) {
  const byId = new Map();
  for (const event of events) if (!byId.has(event.id)) byId.set(event.id, event);
  const done = new Set(placed ?? []);

  const unmet = new Map();     // id -> number of distinct parents still to be placed
  const children = new Map();  // parent id -> ids of its children in this batch
  for (const event of byId.values()) {
    let count = 0;
    for (const parent of new Set(event.parents ?? [])) {
      if (!byId.has(parent) || done.has(parent)) continue;
      count++;
      const list = children.get(parent);
      if (list) list.push(event.id); else children.set(parent, [event.id]);
    }
    unmet.set(event.id, count);
  }

  const ready = new MinHeap();
  for (const [id, count] of unmet) if (count === 0) ready.push(id);

  const ordered = [];
  while (ready.size > 0) {
    const id = ready.pop();
    ordered.push(byId.get(id));
    for (const child of children.get(id) ?? []) {
      const left = unmet.get(child) - 1;
      unmet.set(child, left);
      if (left === 0) ready.push(child);
    }
  }
  if (ordered.length !== byId.size) throw new Error('canonicalOrder: the events have a cycle in their parents — impossible for content-addressed events');
  return ordered;
}

// A binary min-heap of strings (event ids: lowercase hex, compared as plain strings).
class MinHeap {
  constructor() { this.items = []; }
  get size() { return this.items.length; }
  push(value) {
    const a = this.items;
    a.push(value);
    let i = a.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (a[parent] <= a[i]) break;
      [a[parent], a[i]] = [a[i], a[parent]];
      i = parent;
    }
  }
  pop() {
    const a = this.items;
    const top = a[0];
    const last = a.pop();
    if (a.length > 0) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let smallest = i;
        if (l < a.length && a[l] < a[smallest]) smallest = l;
        if (r < a.length && a[r] < a[smallest]) smallest = r;
        if (smallest === i) break;
        [a[smallest], a[i]] = [a[i], a[smallest]];
        i = smallest;
      }
    }
    return top;
  }
}
