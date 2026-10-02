import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalOrder } from '../src/canonical-order.js';

// Events here are only {id, parents}: the order does not look at anything else.
const ev = (id, parents = []) => ({ id, parents });
const ids = (list) => list.map((e) => e.id);

function shuffle(list, seed) {
  const a = [...list];
  let s = seed;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

test('a parent always comes before its children', () => {
  const events = [ev('c', ['b']), ev('b', ['a']), ev('a'), ev('d', ['a', 'c'])];
  const order = ids(canonicalOrder(events));
  for (const e of events) for (const p of e.parents) assert.ok(order.indexOf(p) < order.indexOf(e.id), `${p} before ${e.id}`);
});

test('two events that know nothing of each other: the smaller id goes first, whichever arrived first', () => {
  assert.deepEqual(ids(canonicalOrder([ev('b'), ev('a')])), ['a', 'b']);
  assert.deepEqual(ids(canonicalOrder([ev('a'), ev('b')])), ['a', 'b']);
});

test('the same events give the same order whatever order they are handed in (200 shuffles of a graph with many branches)', () => {
  // Three branches from a common root that fork, cross and re-join.
  const events = [
    ev('00'), ev('f1', ['00']), ev('0a', ['00']), ev('9c', ['00']),
    ev('b2', ['f1']), ev('11', ['0a']), ev('e0', ['9c', 'f1']), ev('05', ['11', 'b2']), ev('a7', ['e0']), ev('ff', ['05', 'a7']),
    ev('21'), ev('d4', ['21']), // a separate root, concurrent with everything above
  ];
  const expected = ids(canonicalOrder(events));
  for (let seed = 1; seed <= 200; seed++) assert.deepEqual(ids(canonicalOrder(shuffle(events, seed))), expected);
  for (const e of events) for (const p of e.parents) assert.ok(expected.indexOf(p) < expected.indexOf(e.id));
});

test('a duplicate is kept once', () => {
  assert.deepEqual(ids(canonicalOrder([ev('a'), ev('b', ['a']), ev('a')])), ['a', 'b']);
});

test('a parent that is neither in the batch nor placed (pruned history) counts as satisfied', () => {
  assert.deepEqual(ids(canonicalOrder([ev('b', ['gone']), ev('a', ['also-gone'])])), ['a', 'b']);
});

test('`placed`: what was folded before this batch is already satisfied, and the order is that of the batch alone', () => {
  const batch = [ev('d', ['x']), ev('c', ['d']), ev('e', ['x'])];
  assert.deepEqual(ids(canonicalOrder(batch, { placed: ['x'] })), ['d', 'c', 'e']);
});

test('a cycle (impossible for content-addressed events) throws rather than loops', () => {
  assert.throws(() => canonicalOrder([ev('a', ['b']), ev('b', ['a'])]), /cycle/);
});

test('an event with a parents field missing is a root', () => {
  assert.deepEqual(ids(canonicalOrder([{ id: 'b' }, { id: 'a', parents: undefined }])), ['a', 'b']);
});
