import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FixedPointError, FRAC_BITS, SCALE, LN2,
  bitLengthNonNeg, mulFixed, divFixed,
  numberToFixed, fixedToNumber, lnFixed, expFixed, powFixed,
} from '../src/fixed-point-math.js';

// A tolerance far tighter than reward.js's own 18-decimal on-chain
// precision needs (units.js), but loose enough to absorb the one
// non-reproducible step in this whole chain: fixedToNumber's own
// BigInt-to-double conversion, done purely for convenience of comparing
// against Math.log/Math.exp/Math.pow in these tests.
function relErr(actual, expected) {
  if (expected === 0) return Math.abs(actual);
  return Math.abs((actual - expected) / expected);
}
function assertClose(actual, expected, tol = 1e-12, msg = '') {
  const err = relErr(actual, expected);
  assert.ok(err < tol, `${msg} expected ${expected}, got ${actual}, relative error ${err}`);
}

test('SCALE is exactly 2^FRAC_BITS', () => {
  assert.equal(SCALE, 1n << FRAC_BITS);
});

test('bitLengthNonNeg matches hand-computable cases', () => {
  assert.equal(bitLengthNonNeg(0n), 0n);
  assert.equal(bitLengthNonNeg(1n), 1n);
  assert.equal(bitLengthNonNeg(2n), 2n);
  assert.equal(bitLengthNonNeg(3n), 2n);
  assert.equal(bitLengthNonNeg(4n), 3n);
  assert.equal(bitLengthNonNeg((1n << 127n)), 128n);
  assert.equal(bitLengthNonNeg((1n << 127n) - 1n), 127n);
});

test('bitLengthNonNeg rejects a negative input rather than silently looping forever', () => {
  assert.throws(() => bitLengthNonNeg(-1n), FixedPointError);
});

test('mulFixed and divFixed round-trip an exact integer', () => {
  const a = numberToFixed(7);
  const b = numberToFixed(3);
  const product = mulFixed(a, b);
  assert.equal(fixedToNumber(product), 21);
  const quotient = divFixed(product, b);
  assert.equal(fixedToNumber(quotient), 7);
});

test('numberToFixed represents small integers exactly', () => {
  for (const n of [0, 1, 2, 1000, 1_000_000, 112_000_000]) {
    assert.equal(numberToFixed(n), BigInt(n) << FRAC_BITS);
  }
});

test('numberToFixed represents negative integers exactly, sign tracked separately from magnitude', () => {
  assert.equal(numberToFixed(-5), -(5n << FRAC_BITS));
});

test('numberToFixed rejects non-finite input', () => {
  assert.throws(() => numberToFixed(NaN), FixedPointError);
  assert.throws(() => numberToFixed(Infinity), FixedPointError);
  assert.throws(() => numberToFixed(-Infinity), FixedPointError);
});

test('numberToFixed / fixedToNumber round-trips a real decimal within double precision', () => {
  for (const v of [1.1, 2.2, 0.4, 33 ** 3, 0.001, 123456.789]) {
    assertClose(fixedToNumber(numberToFixed(v)), v, 1e-14, `round-trip ${v}`);
  }
});

test('LN2 matches Math.LN2 within double precision, derived rather than hardcoded', () => {
  assertClose(fixedToNumber(LN2), Math.LN2, 1e-15);
});

test('lnFixed matches Math.log across a real range, including sub-1 and very large values', () => {
  const values = [1, 2, 3, 10, 100, 1e6, 1e9, 1e15, 0.5, 0.1, 0.001, 1.0000001];
  for (const v of values) {
    const got = fixedToNumber(lnFixed(numberToFixed(v)));
    assertClose(got, Math.log(v), 1e-13, `ln(${v})`);
  }
});

test('lnFixed(1) is exactly zero, not merely close to it', () => {
  assert.equal(lnFixed(SCALE), 0n);
});

test('lnFixed rejects zero and negative input, same domain Math.log itself has (as -Infinity/NaN)', () => {
  assert.throws(() => lnFixed(0n), FixedPointError);
  assert.throws(() => lnFixed(-SCALE), FixedPointError);
});

test('expFixed matches Math.exp across a real range, including negative arguments', () => {
  const values = [0, 1, -1, 2, -2, 10, -10, 27.3, 0.0001, -0.0001, 50, -50];
  for (const v of values) {
    const got = fixedToNumber(expFixed(numberToFixed(v)));
    assertClose(got, Math.exp(v), 1e-13, `exp(${v})`);
  }
});

test('expFixed(0) is exactly 1, not merely close to it', () => {
  assert.equal(expFixed(0n), SCALE);
});

test('expFixed stays positive for exponents well within Q128 range', () => {
  assert.ok(expFixed(numberToFixed(-80)) > 0n);
});

test('expFixed underflows cleanly to exactly zero below Q128\'s own representable floor, rather than a wrong nonzero value', () => {
  // exp(-1000) is a real, positive number (~10^-435) — just one Q128
  // cannot represent at all, since its smallest positive value is
  // 2^-128 (~2.9e-39). This is an inherent property of fixed-point (a
  // fixed number of fractional bits, unlike a float's own floating
  // exponent), not a bug — and never hit by reward.js itself, whose own
  // three powFixed calls all use non-negative exponents by construction.
  assert.equal(expFixed(numberToFixed(-1000)), 0n);
});

test('exp(ln(x)) round-trips x for a real range of values', () => {
  for (const v of [1, 2, 100, 1e9, 0.3, 12345.6789]) {
    const got = fixedToNumber(expFixed(lnFixed(numberToFixed(v))));
    assertClose(got, v, 1e-13, `exp(ln(${v}))`);
  }
});

test('powFixed matches Math.pow for fractional exponents — the exact case Math.pow itself cannot guarantee reproducibly', () => {
  const cases = [[2, 10], [2, 1.1], [1_000_000, 2.2], [1_000_000_000, 1.32], [35937 + 1, 3], [1, 5], [5, 0], [0.5, 2.2]];
  for (const [a, b] of cases) {
    const got = fixedToNumber(powFixed(numberToFixed(a), numberToFixed(b)));
    assertClose(got, Math.pow(a, b), 1e-12, `${a}^${b}`);
  }
});

test('powFixed rejects a non-positive base, the identical domain restriction lnFixed itself has', () => {
  assert.throws(() => powFixed(0n, numberToFixed(2)), FixedPointError);
  assert.throws(() => powFixed(-SCALE, numberToFixed(2)), FixedPointError);
});

test('THE REAL CASE THIS MODULE EXISTS FOR: one full year of continuous domain progression (~112M epochs) stays accurate to double precision, never overflowing', () => {
  const A = 112_000_000;
  const beta = 2.2, T = 0.2;
  const exponent = beta * (1 - T);
  const got = fixedToNumber(powFixed(numberToFixed(A), numberToFixed(exponent)));
  assertClose(got, Math.pow(A, exponent), 1e-12);
});

test('determinism: the identical inputs always yield the identical Fixed BigInt, not just a numerically close one', () => {
  const a = numberToFixed(112_000_000);
  const b = numberToFixed(1.76);
  assert.equal(powFixed(a, b), powFixed(a, b));
  assert.equal(lnFixed(a), lnFixed(a));
  assert.equal(expFixed(b), expFixed(b));
});
