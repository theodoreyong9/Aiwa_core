import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectProgressionParentIds, groupEventsByKey } from '../src/contract-scan.js';

function progressionEvent(id, domain, parents) {
  return { id, parents, payload: { type: 'progression', domain } };
}

test('collectProgressionParentIds collects every parent id of every progression event, with no filter', () => {
  const events = [progressionEvent('e1', 'bob', ['prior', 'offer-1']), progressionEvent('e2', 'alice', ['prior2', 'offer-2'])];
  const ids = collectProgressionParentIds(events);
  assert.equal(ids.has('offer-1'), true);
  assert.equal(ids.has('offer-2'), true);
  assert.equal(ids.has('offer-3'), false);
});

test('collectProgressionParentIds ignores non-progression events', () => {
  const events = [{ id: 'e1', parents: ['x'], payload: { type: 'generous-send-offer' } }];
  const ids = collectProgressionParentIds(events);
  assert.equal(ids.size, 0);
});

test('collectProgressionParentIds with a domain filter only collects parents of that domain\'s own progression', () => {
  const events = [progressionEvent('e1', 'bob', ['offer-1']), progressionEvent('e2', 'alice', ['offer-2'])];
  const ids = collectProgressionParentIds(events, { domain: 'bob' });
  assert.equal(ids.has('offer-1'), true);
  assert.equal(ids.has('offer-2'), false);
});

test('collectProgressionParentIds with an "only" set restricts the result to members of that set', () => {
  const events = [progressionEvent('e1', 'bob', ['offer-1', 'offer-2'])];
  const ids = collectProgressionParentIds(events, { only: new Set(['offer-1']) });
  assert.equal(ids.has('offer-1'), true);
  assert.equal(ids.has('offer-2'), false);
});

test('collectProgressionParentIds can combine domain and only filters', () => {
  const events = [progressionEvent('e1', 'bob', ['offer-1']), progressionEvent('e2', 'alice', ['offer-1'])];
  const ids = collectProgressionParentIds(events, { domain: 'alice', only: new Set(['offer-1']) });
  assert.equal(ids.has('offer-1'), true);
  const idsForBob = collectProgressionParentIds(events, { domain: 'charlie', only: new Set(['offer-1']) });
  assert.equal(idsForBob.size, 0);
});

test('groupEventsByKey groups matching events by key, in real event order', () => {
  const events = [
    { id: 'e1', payload: { type: 'x', target: 'a', n: 1 } },
    { id: 'e2', payload: { type: 'x', target: 'a', n: 2 } },
    { id: 'e3', payload: { type: 'x', target: 'b', n: 3 } },
    { id: 'e4', payload: { type: 'y', target: 'a', n: 4 } },
  ];
  const groups = groupEventsByKey(events, {
    predicate: (ev) => ev.payload.type === 'x',
    keyOf: (ev) => ev.payload.target,
  });
  assert.deepEqual(Object.keys(groups), ['a', 'b']);
  assert.equal(groups.a.length, 2);
  assert.equal(groups.a[0].n, 1);
  assert.equal(groups.a[1].n, 2);
  assert.equal(groups.b.length, 1);
});

test('groupEventsByKey defaults each pushed item to the event\'s own payload', () => {
  const events = [{ id: 'e1', payload: { type: 'x', target: 'a' } }];
  const groups = groupEventsByKey(events, { predicate: (ev) => ev.payload.type === 'x', keyOf: (ev) => ev.payload.target });
  assert.deepEqual(groups.a, [{ type: 'x', target: 'a' }]);
});

test('groupEventsByKey applies itemOf to transform each pushed item', () => {
  const events = [{ id: 'e1', payload: { type: 'x', target: 'a' } }];
  const groups = groupEventsByKey(events, {
    predicate: (ev) => ev.payload.type === 'x',
    keyOf: (ev) => ev.payload.target,
    itemOf: (ev) => ({ id: ev.id, ...ev.payload }),
  });
  assert.deepEqual(groups.a, [{ id: 'e1', type: 'x', target: 'a' }]);
});

test('groupEventsByKey skips a matched event whose key is undefined or null', () => {
  const events = [
    { id: 'e1', payload: { type: 'x', target: undefined } },
    { id: 'e2', payload: { type: 'x', target: null } },
    { id: 'e3', payload: { type: 'x', target: 'a' } },
  ];
  const groups = groupEventsByKey(events, { predicate: (ev) => ev.payload.type === 'x', keyOf: (ev) => ev.payload.target });
  assert.deepEqual(Object.keys(groups), ['a']);
});
