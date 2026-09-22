// The real DataStore — what applications actually use. Never the
// real source of truth: it is a real, rebuildable projection over
// the real EventLog, via a real Materializer. `EventLog` keeps A and
// B; `DataStore` only ever shows the real, current, reduced result.

import { createEvent } from './event.js';
import { defaultKvMaterializer } from './materializer.js';

export class DataStore {
  constructor({ identity, domain, log, materializer = defaultKvMaterializer }) {
    this.identity = identity;
    this.domain = domain;
    this.log = log;
    this.materializer = materializer;
    this._state = materializer.initialState();
    this._listeners = new Set();
  }

  /** Real, exact key lookup against the real, currently-materialized state. */
  async get(key) {
    return this._state[key];
  }
  async has(key) {
    return key in this._state;
  }
  async keys() {
    return Object.keys(this._state);
  }

  /** Real, atomic: constructs a real event, appends it, applies it, notifies — never a direct, un-eventful mutation. */
  async set(key, value) {
    await this._commit({ type: 'kv.set', payload: { key, value } });
  }
  async delete(key) {
    await this._commit({ type: 'kv.delete', payload: { key } });
  }

  /**
   * The real, atomic transaction — every real mutation inside `fn`
   * becomes exactly one real event, never several separate ones to
   * synchronize independently.
   */
  async transact(fn) {
    const ops = [];
    const tx = {
      set: (key, value) => ops.push({ type: 'kv.set', payload: { key, value } }),
      delete: (key) => ops.push({ type: 'kv.delete', payload: { key } }),
    };
    fn(tx);
    await this._commit({ type: 'kv.transaction', payload: { ops } });
  }

  async _commit(partial) {
    const heads = await this.log.head();
    const event = await createEvent(this.identity, { domain: this.domain, parents: heads, ...partial });
    await this.log.append(event);
    await this._apply(event);
  }

  /** Real, applies one already-appended real event — used both for this store's own real writes, and for real events arriving via replication. */
  async _apply(event) {
    if (event.type === 'kv.transaction') {
      for (const op of event.payload.ops) this._state = this.materializer.apply(this._state, op);
    } else {
      this._state = this.materializer.apply(this._state, event);
    }
    for (const fn of this._listeners) fn({ event, state: this._state });
  }

  /** Real, full rebuild from the real, complete EventLog — never trusts any real, cached, in-memory state. */
  async rebuild() {
    this._state = this.materializer.initialState();
    const allIds = await this.log.backend.allIds();
    // A real, simple topological pass — matches EventLog.appendMany's own real approach.
    const events = await Promise.all(allIds.map((id) => this.log.get(id)));
    const applied = new Set();
    let progressed = true;
    const pending = [...events];
    while (pending.length > 0 && progressed) {
      progressed = false;
      for (let i = pending.length - 1; i >= 0; i--) {
        const ev = pending[i];
        if (ev.parents.every((p) => applied.has(p))) {
          await this._apply(ev);
          applied.add(ev.id);
          pending.splice(i, 1);
          progressed = true;
        }
      }
    }
  }

  subscribe(handler) {
    this._listeners.add(handler);
    return () => this._listeners.delete(handler);
  }
}
