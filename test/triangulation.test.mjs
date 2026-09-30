import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScenarios, keypair, link, honestChain } from '../experiments/triangulation-scenarios.mjs';
import { triangulate, judgeSelfReport, assessPosition, replayProgression } from '../src/index.js';
import { initialMirrorState } from '../src/mirror.js';
import { initialIdentityCostState } from '../src/identity-cost.js';

// EXPERIMENTAL (src/triangulation.js, src/position.js). These tests pin what the comparison found on the synthetic
// worlds of experiments/triangulation-scenarios.mjs — including the world where the check cannot be a chain check.
const rows = await runScenarios();
const row = (name) => rows.find((r) => r.name.startsWith(name));

test('no evidence: nothing to triangulate, nothing to accuse, no position', async () => {
  assert.equal(await triangulate(initialMirrorState(), [], 'target'), null);
  const judged = judgeSelfReport(20, null);
  assert.deepEqual([judged.contradicted, judged.forked, judged.ahead], [false, false, null]);
  const assessed = await assessPosition({ mirrorState: initialMirrorState(), identityCostState: initialIdentityCostState(), orderedEvents: [], targetDomain: 'target', selfReportedEpoch: 20 });
  assert.deepEqual([assessed.position, assessed.accuse, assessed.estimate, assessed.proof], [null, false, null, null]);
});

test('honest world: every rule finds the truth, and the combination checked the chain', () => {
  const r = row('honest world');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound, r.combined.position, r.combined.verification], [20, 20, 20, 'chain']);
});

test('a funded majority that only saw an old state drags the median down and makes its check accuse an honest X; the combination reports the proven 20', () => {
  const r = row('funded majority saw only an OLD');
  assert.equal(r.weighted.tick, 4);
  assert.equal(r.weighted.consistent, false);
  assert.equal(r.combined.position, 20);
  assert.equal(r.combined.accuse, false);
  assert.equal(r.combined.staleEstimate, true, 'and it says the estimate lagged behind a proof');
});

test('unfunded observers cannot lower the bound; and unfunded observers alone still establish it (the weighted median has no tick at all)', () => {
  assert.equal(row('unfunded observers who saw').combined.position, 20);
  const only = row('ONLY unfunded');
  assert.equal(only.weighted.tick, null);
  assert.equal(only.combined.position, 20);
});

test('a domain that rewinds is contradicted by one honest witness, even when a funded majority agrees with the rewind', () => {
  const r = row('X rewinds');
  assert.equal(r.weighted.tick, 10);
  assert.equal(r.weighted.consistent, true, 'the vote makes the rewind look consistent');
  assert.equal(r.combined.contradicted, true);
  assert.equal(r.combined.accuse, true);
  assert.equal(r.combined.proof.witnesses[0].eventId, 'e20', 'and the evidence is the event itself');
});

test('a fork is provable from what observers hold — although the linear chain rejects the second lineage — and the weighted median has no notion of it', () => {
  const r = row('X holds two unrelated');
  assert.equal(r.weighted.tick, 21);
  assert.equal(r.combined.forked, true);
  assert.deepEqual(new Set([r.combined.forks[0].a, r.combined.forks[0].b]), new Set(['e21a', 'e21b']));
  assert.equal(r.combined.position, 21, 'the accepted lineage still sets the position');
  assert.ok(r.combined.rejectedEvents.includes('e21b'), 'the rejected lineage is reported');
});

test('a reference to an event that does not exist proves nothing, for any rule', () => {
  const r = row('observer cites an event that does not exist');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound, r.combined.position], [20, 20, 20]);
});

test('LIMIT: only stale observers — being ahead is reported, not called wrong; the median check calls it inconsistent', () => {
  const r = row('only stale observers');
  assert.equal(r.combined.position, 4);
  assert.equal(r.combined.ahead, 16);
  assert.equal(r.combined.accuse, false);
  assert.equal(r.weighted.consistent, false);
});

test('a forged event of X (signed by someone else) fools the proofs when the log is trusted, fools the median when a funded majority cites it, and does not fool the combination', () => {
  const minority = row('FORGED epoch-999999 event (signed by someone else); a funded MINORITY');
  assert.equal(minority.weighted.tick, 20, 'the weight resists a minority');
  assert.equal(minority.triang.lowerBound, 999999, 'proofs alone, trusting the log, are fooled');
  assert.equal(minority.combined.position, 20);
  assert.deepEqual(minority.combined.rejectedEvents, ['e-forged'], 'the forged event is reported, by id');
  const majority = row('FORGED epoch-999999 event (signed by someone else); a funded MAJORITY');
  assert.equal(majority.weighted.tick, 999999, 'the weight does not resist a funded majority');
  assert.equal(majority.weighted.consistent, false);
  assert.equal(majority.combined.position, 20);
  assert.equal(majority.combined.accuse, false);
});

test('the target SIGNING a far-ahead event without doing the sequential work: every other rule is fooled, the chain replay is not', () => {
  const r = row('X SIGNS a fake far-ahead event itself');
  assert.deepEqual([r.weighted.tick, r.triang.lowerBound], [999999, 999999]);
  assert.equal(r.combined.position, 20);
  assert.equal(r.combined.verification, 'chain');
  assert.deepEqual(r.combined.rejectedEvents, ['e-self-fake']);
  assert.equal(r.combined.accuse, false);
});

test('LIMIT: a reader that does not hold the history from epoch 1 cannot replay the chain — it falls back to the signature, SAYS so, and colluders with the target can fool it', () => {
  const r = row('same, but the reader holds only epochs 15-20');
  assert.equal(r.combined.verification, 'signature');
  assert.equal(r.combined.position, 999999);
});

test("replayProgression accepts a real chain, rejects the target's own fake for the work it lacks, and says when it cannot chain at all", async () => {
  const t = await keypair();
  const chain = await honestChain(t, 5);
  const fake = await link(t, t, 'fake', 999, chain[4], { vdfOutput: 'f'.repeat(64) });
  const replay = await replayProgression([...chain, fake], t.domain);
  assert.deepEqual([...replay.accepted], ['e1', 'e2', 'e3', 'e4', 'e5']);
  assert.equal(replay.genesis, true);
  assert.equal(replay.rejections.length, 1);
  assert.equal(replay.rejections[0].eventId, 'fake');

  // a real but partial history (from epoch 3): nothing can be chained, and it is not the same as "forged"
  const partial = await replayProgression(chain.slice(2), t.domain);
  assert.equal(partial.genesis, false);
  assert.equal(partial.accepted.size, 0);

  // a sequential proof that does not match: rejected even though the signature is genuine
  const badWork = await link(t, t, 'bad-work', 6, chain[4], { vdfOutput: 'a'.repeat(64) });
  assert.equal((await replayProgression([...chain, badWork], t.domain)).accepted.has('bad-work'), false);
});
