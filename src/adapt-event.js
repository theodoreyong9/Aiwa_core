// Bridges @aiwa/record's wire event shape — {id, domain, author,
// authorPublicKey, parents, type, payload, createdAt, signature},
// self-verifying and transport-ready — to the reducers in this
// package's own, simpler internal convention: {id, parents, payload},
// with `type` folded inside `payload`. The reducers below (wallet,
// accrual, progression, causal-tick, mirror, ...) only ever care about
// payload semantics for state transitions; they have no reason to
// carry signature/author bytes through every fold. This is the one
// seam between the two, so every reducer stays a near-verbatim,
// independently-testable state machine.
export function toReducerEvent(recordEvent) {
  return {
    id: recordEvent.id,
    parents: recordEvent.parents,
    payload: { type: recordEvent.type, ...recordEvent.payload },
  };
}

export function toReducerEvents(recordEvents) {
  return recordEvents.map(toReducerEvent);
}
