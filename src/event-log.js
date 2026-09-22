// The real, deliberately "stupid" EventLog — stores real events,
// nothing more. A real device can run this entirely alone: no
// network, no server. Storage-backend-agnostic by real design (a
// real, working in-memory backend for tests and server-side use; a
// real IndexedDB backend for the browser) — applications never know
// or care which real backend is in use.

import { verifyEvent } from './event.js';

/** A real, minimal storage contract any real backend must satisfy. */
export function createMemoryBackend() {
  const events = new Map();
  return {
    async putEvent(event) { events.set(event.id, event); },
    async getEvent(id) { return events.get(id) ?? null; },
    async hasEvent(id) { return events.has(id); },
    async allIds() { return [...events.keys()]; },
  };
}

/** A real IndexedDB-backed store — for real, persistent, browser-side use. */
export function createIndexedDbBackend(dbName = 'aiwa-core-event-log') {
  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => { req.result.createObjectStore('events', { keyPath: 'id' }); };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return {
    async putEvent(event) {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('events', 'readwrite');
        tx.objectStore('events').put(event);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    },
    async getEvent(id) {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const req = db.transaction('events', 'readonly').objectStore('events').get(id);
        req.onsuccess = () => resolve(req.result ?? null);
        req.onerror = () => reject(req.error);
      });
    },
    async hasEvent(id) {
      return (await this.getEvent(id)) !== null;
    },
    async allIds() {
      const db = await openDb();
      return new Promise((resolve, reject) => {
        const req = db.transaction('events', 'readonly').objectStore('events').getAllKeys();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },
  };
}

export class EventLog {
  constructor(backend = createMemoryBackend()) {
    this.backend = backend;
  }

  async append(event) {
    if (await this.backend.hasEvent(event.id)) return; // a real, already-known event is a real no-op, never a duplicate
    // Real, mandatory verification, enforced here, unconditionally,
    // for every real event, regardless of its real source (a local
    // commit, a Replicator, or any future caller). No trust
    // shortcut, no exception.
    const verification = await verifyEvent(event);
    if (!verification.valid) throw new Error(`Cannot append: real event ${event.id} failed real verification — ${verification.reason}`);
    for (const p of event.parents) {
      if (!(await this.backend.hasEvent(p))) throw new Error(`Cannot append: real parent ${p} is not yet known — request it first.`);
    }
    await this.backend.putEvent(event);
  }

  async appendMany(events) {
    // Real, topological pass: keep retrying real events whose real
    // parents were just appended in this same real batch, rather
    // than requiring the caller to pre-sort.
    const pending = [...events];
    let progressed = true;
    while (pending.length > 0 && progressed) {
      progressed = false;
      for (let i = pending.length - 1; i >= 0; i--) {
        const ev = pending[i];
        const parentsKnown = await Promise.all(ev.parents.map((p) => this.backend.hasEvent(p)));
        if (parentsKnown.every(Boolean)) {
          await this.append(ev);
          pending.splice(i, 1);
          progressed = true;
        }
      }
    }
    if (pending.length > 0) throw new Error(`appendMany: ${pending.length} real event(s) have real, unresolvable missing parents.`);
  }

  async get(id) { return this.backend.getEvent(id); }
  async has(id) { return this.backend.hasEvent(id); }

  async getParents(id) {
    const event = await this.get(id);
    if (!event) return [];
    return Promise.all(event.parents.map((p) => this.get(p)));
  }

  /**
   * The real, current heads — every real, known event that is not yet
   * a real parent of any other real, known event. Computed fresh from
   * the backend every call, deliberately never cached across calls or
   * instances: a real, persisted backend (IndexedDB) outlives any one
   * in-memory EventLog instance — a page reload, a service worker
   * restart, or a new process all construct a fresh EventLog over the
   * same real backend, so any cache not itself rebuilt from the
   * backend would silently go stale the instant that happens.
   */
  async head() {
    const ids = await this.backend.allIds();
    const childCount = new Map();
    for (const id of ids) {
      const event = await this.backend.getEvent(id);
      for (const p of event.parents) childCount.set(p, (childCount.get(p) ?? 0) + 1);
    }
    return ids.filter((id) => (childCount.get(id) ?? 0) === 0);
  }

  /** Real, new events not reachable as a real ancestor of `knownIds` — the real, minimal set a peer announcing `knownIds` as their own heads is genuinely missing. */
  async *since(knownIds) {
    const closure = new Set();
    const stack = [...knownIds];
    while (stack.length > 0) {
      const id = stack.pop();
      if (closure.has(id)) continue;
      closure.add(id);
      const event = await this.get(id);
      if (event) stack.push(...event.parents);
    }
    const allIds = await this.backend.allIds();
    for (const id of allIds) {
      if (!closure.has(id)) yield await this.get(id);
    }
  }
}
