import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareChurnVsStay, findMostProfitableChurnInterval } from '../src/churn-analysis.js';
import { linearCostCurve } from '../src/identity-cost.js';

const params = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

test('rejects non-positive S, totalEpochs, or churnInterval', () => {
  const curve = () => 1;
  assert.throws(() => compareChurnVsStay(params, curve, { S: 0, totalEpochs: 100, churnInterval: 10 }));
  assert.throws(() => compareChurnVsStay(params, curve, { S: 10, totalEpochs: 0, churnInterval: 10 }));
  assert.throws(() => compareChurnVsStay(params, curve, { S: 10, totalEpochs: 100, churnInterval: 0 }));
});

test('THE REAL, MEASURED VULNERABILITY: with zero real identity cost, churn genuinely beats staying', () => {
  const zeroCost = () => 0;
  const result = compareChurnVsStay(params, zeroCost, { S: 10, totalEpochs: 1000, churnInterval: 50 });
  assert.ok(result.churnProfitable, 'confirms the reward formula\'s own young-domain advantage is real and exploitable absent any real cost to it');
  assert.ok(result.churnNet > result.stayNet);
});

test('an inadequately small real identity cost still leaves churn profitable', () => {
  const cheapCurve = linearCostCurve({ baseLamports: 0.01, lamportsPerSlot: 0 });
  const result = compareChurnVsStay(params, cheapCurve, { S: 10, totalEpochs: 1000, churnInterval: 50 });
  assert.ok(result.churnProfitable, 'a real but tiny cost does not automatically close a real economic advantage — magnitude matters, not mere existence');
});

test('THE REAL, VERIFIED CLOSURE: a properly-dimensioned real identity cost makes churn genuinely unprofitable', () => {
  const realCurve = linearCostCurve({ baseLamports: 2, lamportsPerSlot: 0 });
  const result = compareChurnVsStay(params, realCurve, { S: 10, totalEpochs: 1000, churnInterval: 50 });
  assert.equal(result.churnProfitable, false, 'with this real cost, repeatedly restarting nets LESS than staying — a real, measured, parameter-specific closure, not an assumed one');
  assert.ok(result.churnNet < 0, 'churn should be net-negative here, not merely less good than staying');
});

test('a slot-scaling real cost curve makes later, more frequent churn cycles progressively more expensive', () => {
  const scalingCurve = linearCostCurve({ baseLamports: 0.5, lamportsPerSlot: 0.01 });
  const shortInterval = compareChurnVsStay(params, scalingCurve, { S: 10, totalEpochs: 1000, churnInterval: 20 });
  const longInterval = compareChurnVsStay(params, scalingCurve, { S: 10, totalEpochs: 1000, churnInterval: 200 });
  assert.ok(shortInterval.churnTotalCost > longInterval.churnTotalCost, 'more frequent real restarts must accumulate more real total cost');
});

test('findMostProfitableChurnInterval identifies the real best-case for an attacker, across a real range of intervals', () => {
  const zeroCost = () => 0;
  const best = findMostProfitableChurnInterval(params, zeroCost, {
    S: 10, totalEpochs: 1000, candidateIntervals: [10, 25, 50, 100, 200, 500],
  });
  assert.ok(best.churnProfitable);
  assert.ok(params && best.interval > 0);
});

test('findMostProfitableChurnInterval confirms no real interval beats staying once the real cost is properly dimensioned', () => {
  const realCurve = linearCostCurve({ baseLamports: 2, lamportsPerSlot: 0 });
  const best = findMostProfitableChurnInterval(params, realCurve, {
    S: 10, totalEpochs: 1000, candidateIntervals: [5, 10, 25, 50, 100, 200, 500, 900],
  });
  assert.equal(best.churnProfitable, false, 'not even the real, single best-case interval for an attacker should beat staying, once real cost is properly dimensioned');
});

test('findMostProfitableChurnInterval ignores real intervals outside the valid range without throwing', () => {
  const curve = () => 1;
  const best = findMostProfitableChurnInterval(params, curve, {
    S: 10, totalEpochs: 100, candidateIntervals: [-5, 0, 50, 200, 1000],
  });
  assert.ok(best);
  assert.equal(best.interval, 50);
});
