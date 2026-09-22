// The real Materializer contract — an application decides what a
// real event means; the event/log layer never does. A real, default
// key-value Materializer is provided for the common, real case, but
// any real application can supply its own, richer real reducer
// instead (see mirror.js/wallet.js/etc. in this very package, which
// each fold events with their own real state machines, never this
// generic one).

/**
 * The real, default key-value Materializer — handles `kv.set` and
 * `kv.delete` real event types. `apply` is a real, pure function:
 * (state, event) -> new state, never mutating its real input.
 */
export const defaultKvMaterializer = {
  initialState: () => ({}),
  apply(state, event) {
    if (event.type === 'kv.set') return { ...state, [event.payload.key]: event.payload.value };
    if (event.type === 'kv.delete') {
      const { [event.payload.key]: _, ...rest } = state;
      return rest;
    }
    return state; // a real, unrecognized event type is a real no-op here, never an error — a real, custom Materializer may still care about it elsewhere
  },
};
