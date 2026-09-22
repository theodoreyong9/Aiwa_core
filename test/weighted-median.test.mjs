import { test } from 'node:test';
import assert from 'node:assert/strict';
import { weightedMedian } from '../src/weighted-median.js';

test('matches a plain median for equal weights', () => {
  const estimates = [1, 2, 3, 4, 5].map((value) => ({ value, weight: 1 }));
  assert.equal(weightedMedian(estimates), 3);
});

test('a single estimate is its own median', () => {
  assert.equal(weightedMedian([{ value: 42, weight: 1 }]), 42);
});

test('heavier weight pulls the median toward it', () => {
  const estimates = [{ value: 1, weight: 1 }, { value: 2, weight: 1 }, { value: 100, weight: 10 }];
  assert.equal(weightedMedian(estimates), 100);
});

test('rejects an empty estimate list', () => {
  assert.throws(() => weightedMedian([]));
});

test('rejects zero total weight', () => {
  assert.throws(() => weightedMedian([{ value: 1, weight: 0 }]));
});

test('THE REAL PROPERTY: a minority of weight cannot pull the result to an arbitrary value', () => {
  const honest = [{ value: 98, weight: 20 }, { value: 100, weight: 20 }, { value: 102, weight: 20 }];
  const adversarial = [{ value: 999999, weight: 39 }];
  const result = weightedMedian([...honest, ...adversarial]);
  assert.ok(result < 200, `adversarial minority pulled the median to ${result}, expected it to stay near the honest cluster`);
});

test('SECURITY: once adversarial weight crosses half, it DOES dominate — the real, documented boundary, not silently hidden', () => {
  const honest = [{ value: 100, weight: 40 }];
  const adversarial = [{ value: 999999, weight: 61 }];
  const result = weightedMedian([...honest, ...adversarial]);
  assert.equal(result, 999999, 'this is the real, honest boundary the design accepts — alpha_A >= 1/2 is explicitly out of scope, not silently protected against');
});

test('ties in cumulative weight resolve to a real, deterministic value, not an arbitrary one', () => {
  const estimates = [{ value: 1, weight: 1 }, { value: 2, weight: 1 }];
  const r1 = weightedMedian(estimates);
  const r2 = weightedMedian(estimates);
  assert.equal(r1, r2);
});
