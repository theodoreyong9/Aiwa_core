import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, prove, verify, RSA_2048_MODULUS } from '../src/wesolowski-vdf.js';

const TEST_N = 9241n * 9257n;

test('a real, honestly-computed VDF proof verifies', async () => {
  const x = 7n;
  const T = 500;
  const y = evaluate(x, T, TEST_N);
  const proof = await prove(x, T, y, TEST_N);
  assert.equal(await verify(x, T, y, proof, TEST_N), true);
});

test('evaluate is deterministic', () => {
  assert.equal(evaluate(7n, 200, TEST_N), evaluate(7n, 200, TEST_N));
});

test('a different starting x produces a different y for the same T', () => {
  assert.notEqual(evaluate(7n, 200, TEST_N), evaluate(11n, 200, TEST_N));
});

test('a different T produces a different y for the same x', () => {
  assert.notEqual(evaluate(7n, 200, TEST_N), evaluate(7n, 201, TEST_N));
});

test('SECURITY: a fabricated y with no real computation behind it is rejected', async () => {
  const x = 7n;
  const T = 300;
  const y = evaluate(x, T, TEST_N);
  const proof = await prove(x, T, y, TEST_N);
  const fabricatedY = (y + 1n) % TEST_N;
  assert.equal(await verify(x, T, fabricatedY, proof, TEST_N), false);
});

test('SECURITY: a proof computed for fewer real iterations than claimed is rejected', async () => {
  const x = 7n;
  const realY = evaluate(x, 300, TEST_N);
  const shortcutY = evaluate(x, 250, TEST_N);
  const shortcutProof = await prove(x, 250, shortcutY, TEST_N);
  assert.equal(await verify(x, 300, shortcutY, shortcutProof, TEST_N), false);
});

test('SECURITY: a tampered proof (pi altered after the fact) is rejected', async () => {
  const x = 7n;
  const T = 300;
  const y = evaluate(x, T, TEST_N);
  const proof = await prove(x, T, y, TEST_N);
  const tampered = { ...proof, pi: (proof.pi + 1n) % TEST_N };
  assert.equal(await verify(x, T, y, tampered, TEST_N), false);
});

test('SECURITY: a proof with a forged challenge prime l is rejected', async () => {
  const x = 7n;
  const T = 300;
  const y = evaluate(x, T, TEST_N);
  const proof = await prove(x, T, y, TEST_N);
  const tampered = { ...proof, l: proof.l + 2n };
  assert.equal(await verify(x, T, y, tampered, TEST_N), false);
});

test('verify rejects a malformed proof shape without throwing', async () => {
  assert.equal(await verify(7n, 300, 1n, null, TEST_N), false);
  assert.equal(await verify(7n, 300, 1n, {}, TEST_N), false);
  assert.equal(await verify(7n, 300, 1n, { pi: 'not-a-bigint', l: 5n }, TEST_N), false);
});

test('THE REAL PROPERTY: verification time does not scale with iteration count, unlike evaluation time', async () => {
  const x = 7n;
  const smallT = 500;
  const largeT = 8000;

  const evalStartSmall = performance.now();
  const ySmall = evaluate(x, smallT, RSA_2048_MODULUS);
  const evalTimeSmall = performance.now() - evalStartSmall;

  const evalStartLarge = performance.now();
  const yLarge = evaluate(x, largeT, RSA_2048_MODULUS);
  const evalTimeLarge = performance.now() - evalStartLarge;

  const proofSmall = await prove(x, smallT, ySmall, RSA_2048_MODULUS);
  const proofLarge = await prove(x, largeT, yLarge, RSA_2048_MODULUS);

  const verifyStartSmall = performance.now();
  await verify(x, smallT, ySmall, proofSmall, RSA_2048_MODULUS);
  const verifyTimeSmall = performance.now() - verifyStartSmall;

  const verifyStartLarge = performance.now();
  await verify(x, largeT, yLarge, proofLarge, RSA_2048_MODULUS);
  const verifyTimeLarge = performance.now() - verifyStartLarge;

  assert.ok(evalTimeLarge > evalTimeSmall * 5, `eval time should grow with T: small=${evalTimeSmall}ms large=${evalTimeLarge}ms`);
  assert.ok(verifyTimeLarge < evalTimeLarge / 3, `verify must stay cheap even at large T: verify=${verifyTimeLarge}ms eval=${evalTimeLarge}ms`);
});

test('a real end-to-end round trip against the actual RSA-2048 modulus, at a small iteration count for test speed', async () => {
  const x = 7n;
  const T = 50;
  const y = evaluate(x, T, RSA_2048_MODULUS);
  const proof = await prove(x, T, y, RSA_2048_MODULUS);
  assert.equal(await verify(x, T, y, proof, RSA_2048_MODULUS), true);
});
