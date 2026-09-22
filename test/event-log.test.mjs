import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventLog, createMemoryBackend } from '../src/event-log.js';
import { generateIdentity } from '../src/identity.js';
import { createEvent } from '../src/event.js';

// Real events, real signatures — the same identity/event.js this whole
// package uses everywhere else, never a shortcut/fake event shape.
async function realEvent(identity, { domain = 'd', parents = [], type = 'x', payload = {}, createdAt } = {}) {
  return createEvent(identity, { domain, parents, type, payload, ...(createdAt !== undefined ? { createdAt } : {}) });
}

test('append/get/has: a real event round-trips exactly', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const event = await realEvent(identity);
  assert.equal(await log.has(event.id), false);
  await log.append(event);
  assert.equal(await log.has(event.id), true);
  assert.deepEqual(await log.get(event.id), event);
});

test('append is a real no-op for an already-known event, never a duplicate error', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const event = await realEvent(identity);
  await log.append(event);
  await assert.doesNotReject(log.append(event));
});

test('append rejects a real event whose parent is not yet known', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const orphan = await realEvent(identity, { parents: ['missing-parent-id'] });
  await assert.rejects(log.append(orphan), /not yet known/);
});

test('append rejects a real event that fails real verification', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const event = await realEvent(identity);
  const tampered = { ...event, payload: { tampered: true } };
  await assert.rejects(log.append(tampered), /failed real verification/);
});

test('head(): a single event with no children is its own head', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity);
  await log.append(e1);
  assert.deepEqual(await log.head(), [e1.id]);
});

test('head(): a real chain of two events reports only the tip as head', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity);
  await log.append(e1);
  const e2 = await realEvent(identity, { parents: [e1.id] });
  await log.append(e2);
  assert.deepEqual(await log.head(), [e2.id]);
});

test('head(): two real, independent branches are both heads', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity, { payload: { n: 1 } });
  const e2 = await realEvent(identity, { payload: { n: 2 } });
  await log.append(e1);
  await log.append(e2);
  assert.deepEqual(new Set(await log.head()), new Set([e1.id, e2.id]));
});

// Regression test: a real, persisted backend (e.g. IndexedDB) outlives
// any one in-memory EventLog instance — a page reload, a service
// worker restart, or a fresh process all construct a brand-new
// EventLog over the same real backend. head() must stay correct across
// that boundary, not just within one instance's own lifetime.
test('head() is correct from a FRESH EventLog instance over an already-populated backend (a real restart)', async () => {
  const identity = await generateIdentity();
  const backend = createMemoryBackend(); // stands in for a real, persisted backend surviving a restart
  const sessionOne = new EventLog(backend);
  const e1 = await realEvent(identity, { payload: { n: 1 } });
  await sessionOne.append(e1);
  const e2 = await realEvent(identity, { parents: [e1.id], payload: { n: 2 } });
  await sessionOne.append(e2);

  const sessionTwo = new EventLog(backend); // a brand-new instance, same real backend — this is the "restart"
  assert.deepEqual(await sessionTwo.head(), [e2.id], 'must report only the true tip, not every known event, after a restart');
});

test('appendMany(): out-of-order real events are topologically resolved', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity, { payload: { n: 1 } });
  const e2 = await realEvent(identity, { parents: [e1.id], payload: { n: 2 } });
  const e3 = await realEvent(identity, { parents: [e2.id], payload: { n: 3 } });
  await log.appendMany([e3, e1, e2]); // deliberately out of causal order
  assert.deepEqual(await log.head(), [e3.id]);
});

test('appendMany(): a real, unresolvable missing parent throws rather than silently dropping events', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const orphan = await realEvent(identity, { parents: ['missing-parent-id'] });
  await assert.rejects(log.appendMany([orphan]), /unresolvable missing parents/);
});

test('since(): reports only real events not reachable from the given known ids', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity, { payload: { n: 1 } });
  await log.append(e1);
  const e2 = await realEvent(identity, { parents: [e1.id], payload: { n: 2 } });
  await log.append(e2);
  const e3 = await realEvent(identity, { parents: [e2.id], payload: { n: 3 } });
  await log.append(e3);

  const missing = [];
  for await (const event of log.since([e1.id])) missing.push(event.id);
  assert.deepEqual(new Set(missing), new Set([e2.id, e3.id]));
});

test('since(): reports nothing missing once the given known ids already cover every real event', async () => {
  const identity = await generateIdentity();
  const log = new EventLog();
  const e1 = await realEvent(identity);
  await log.append(e1);
  const missing = [];
  for await (const event of log.since([e1.id])) missing.push(event.id);
  assert.deepEqual(missing, []);
});
