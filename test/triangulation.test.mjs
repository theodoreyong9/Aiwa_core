import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScenarios } from '../experiments/triangulation-scenarios.mjs';
import { triangulate, judgeSelfReport } from '../src/triangulation.js';
import { initialMirrorState } from '../src/mirror.js';

// PROTOTYPE (src/triangulation.js). These tests pin what the comparison found on the synthetic worlds of
// experiments/triangulation-scenarios.mjs — including where the triangulation is WORSE than the weighted median.
const rows = await runScenarios();
const row = (name) => rows.find((r) => r.name.startsWith(name));

test('no evidence: nothing to triangulate, nothing to accuse', () => {
  assert.equal(triangulate(initialMirrorState(), [], 'target'), null);
  const judged = judgeSelfReport(100, null);
  assert.deepEqual([judged.contradicted, judged.forked, judged.ahead], [false, false, null]);
});

test('honest world: both rules find the truth', () => {
  const r = row('honest world');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.triangulation.lowerBound, 100);
});

test('a funded majority that only saw an old state drags the median down and makes the median check accuse an honest X; the lower bound does not move', () => {
  const r = row('funded majority saw only an OLD');
  assert.equal(r.weighted.tick, 10);
  assert.equal(r.consistency.consistent, false, 'the weighted check calls the honest domain inconsistent');
  assert.equal(r.triangulation.lowerBound, 100);
  assert.equal(r.judged.contradicted, false);
});

test('observers with no burn: the weight ignores them, and they cannot lower the lower bound either', () => {
  const r = row('unfunded sybils');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.triangulation.lowerBound, 100);
});

test('a domain that rewinds is contradicted by one honest witness, even when a funded majority agrees with the rewind', () => {
  const r = row('X rewinds');
  assert.equal(r.weighted.tick, 50);
  assert.equal(r.consistency.consistent, true, 'the majority makes the rewind look consistent');
  assert.equal(r.judged.contradicted, true);
  assert.equal(r.judged.witnesses[0].eventId, 'e100', 'and the evidence is the event itself');
});

test('a fork is provable from what observers hold, and the weighted median has no notion of it', () => {
  const r = row('X forks');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.judged.forked, true);
  assert.deepEqual(new Set([r.judged.forks[0].a, r.judged.forks[0].b]), new Set(['e100a', 'e100b']));
});

test('a reference to an event that does not exist proves nothing, for either rule', () => {
  const r = row('observer cites an event that does not exist');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.triangulation.lowerBound, 100);
});

test('LIMIT: only stale observers — being ahead is reported, not called wrong; the median check calls it inconsistent', () => {
  const r = row('only stale observers');
  assert.equal(r.triangulation.lowerBound, 10);
  assert.equal(r.judged.ahead, 90);
  assert.equal(r.judged.contradicted, false);
  assert.equal(r.consistency.consistent, false);
});

test('LIMIT: a forged event of X that got into the log FOOLS the triangulation and does not fool the weighted median', () => {
  const r = row('a FORGED');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.triangulation.lowerBound, 999999, 'the lower bound is only as good as the check that admitted the event');
  assert.equal(r.judged.contradicted, true, 'and it would falsely accuse the honest domain');
});
