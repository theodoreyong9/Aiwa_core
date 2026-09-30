import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScenarios } from '../experiments/triangulation-scenarios.mjs';
import { triangulate, judgeSelfReport, assessPosition } from '../src/index.js';
import { initialMirrorState } from '../src/mirror.js';
import { initialIdentityCostState } from '../src/identity-cost.js';

// EXPERIMENTAL (src/triangulation.js, src/position.js). These tests pin what the comparison found on the synthetic
// worlds of experiments/triangulation-scenarios.mjs — including the world where every rule is fooled.
const rows = await runScenarios();
const row = (name) => rows.find((r) => r.name.startsWith(name));

test('no evidence: nothing to triangulate, nothing to accuse, no position', async () => {
  assert.equal(await triangulate(initialMirrorState(), [], 'target'), null);
  const judged = judgeSelfReport(100, null);
  assert.deepEqual([judged.contradicted, judged.forked, judged.ahead], [false, false, null]);
  const assessed = await assessPosition({ mirrorState: initialMirrorState(), identityCostState: initialIdentityCostState(), orderedEvents: [], targetDomain: 'target', selfReportedEpoch: 100 });
  assert.deepEqual([assessed.position, assessed.accuse, assessed.estimate, assessed.proof], [null, false, null, null]);
});

test('honest world: every rule finds the truth', () => {
  const r = row('honest world');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound, r.combined.position], [100, 100, 100]);
});

test('a funded majority that only saw an old state drags the median down and makes its check accuse an honest X; the combination reports the proven 100', () => {
  const r = row('funded majority saw only an OLD');
  assert.equal(r.weighted.tick, 10);
  assert.equal(r.weighted.consistent, false);
  assert.equal(r.combined.position, 100);
  assert.equal(r.combined.accuse, false);
  assert.equal(r.combined.staleEstimate, true, 'and it says the estimate lagged behind a proof');
});

test('unfunded observers cannot lower the bound; and unfunded observers alone still establish it (the weighted median has no tick at all)', () => {
  assert.equal(row('unfunded observers who saw').combined.position, 100);
  const only = row('ONLY unfunded');
  assert.equal(only.weighted.tick, null);
  assert.equal(only.combined.position, 100);
});

test('a domain that rewinds is contradicted by one honest witness, even when a funded majority agrees with the rewind', () => {
  const r = row('X rewinds');
  assert.equal(r.weighted.tick, 50);
  assert.equal(r.weighted.consistent, true, 'the vote makes the rewind look consistent');
  assert.equal(r.combined.contradicted, true);
  assert.equal(r.combined.accuse, true);
  assert.equal(r.combined.proof.witnesses[0].eventId, 'e100', 'and the evidence is the event itself');
});

test('a fork is provable from what observers hold, and the weighted median has no notion of it', () => {
  const r = row('X holds two unrelated');
  assert.equal(r.weighted.tick, 100);
  assert.equal(r.combined.forked, true);
  assert.deepEqual(new Set([r.combined.proof.forks[0].a, r.combined.proof.forks[0].b]), new Set(['e100a', 'e100b']));
});

test('a reference to an event that does not exist proves nothing, for any rule', () => {
  const r = row('observer cites an event that does not exist');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound, r.combined.position], [100, 100, 100]);
});

test('LIMIT: only stale observers — being ahead is reported, not called wrong; the median check calls it inconsistent', () => {
  const r = row('only stale observers');
  assert.equal(r.combined.position, 10);
  assert.equal(r.combined.ahead, 90);
  assert.equal(r.combined.accuse, false);
  assert.equal(r.weighted.consistent, false);
});

test('a forged event of X (signed by someone else) fools the proofs when the log is trusted, fools the median when a funded majority cites it, and does not fool the combination', () => {
  const minority = row('FORGED epoch-999999 event in the log; a funded MINORITY');
  assert.equal(minority.weighted.tick, 100, 'the weight resists a minority');
  assert.equal(minority.triang.lowerBound, 999999, 'proofs alone, trusting the log, are fooled');
  assert.equal(minority.combined.position, 100);
  assert.deepEqual(minority.combined.rejectedEvents, ['e-forged'], 'the forged event is reported, by id');
  const majority = row('FORGED epoch-999999 event in the log; a funded MAJORITY');
  assert.equal(majority.weighted.tick, 999999, 'the weight does not resist a funded majority');
  assert.equal(majority.weighted.consistent, false);
  assert.equal(majority.combined.position, 100);
  assert.equal(majority.combined.accuse, false);
});

test('LIMIT: the target SIGNING a far-ahead event without doing the sequential work fools every rule, because the check is signature-only', () => {
  const r = row('X SIGNS a fake far-ahead');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound, r.combined.position], [999999, 999999, 999999]);
});
