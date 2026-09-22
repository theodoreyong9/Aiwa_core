import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DECIMALS, toUnits, fromUnits, fromFloat, fixedToUnits, format } from '../src/units.js';
import { SCALE, numberToFixed } from '../src/fixed-point-math.js';

test('DECIMALS is 18', () => {
  assert.equal(DECIMALS, 18);
});

test('toUnits converts whole and fractional amounts exactly', () => {
  assert.equal(toUnits('5'), 5000000000000000000n);
  assert.equal(toUnits('5.5'), 5500000000000000000n);
  assert.equal(toUnits('0.000000000000000001'), 1n);
  assert.equal(toUnits('0'), 0n);
  assert.equal(toUnits('-3.5'), -3500000000000000000n);
});

test('toUnits rejects too much precision or malformed input', () => {
  assert.throws(() => toUnits('1.1234567890123456789'));
  assert.throws(() => toUnits('1e10'));
  assert.throws(() => toUnits('abc'));
});

test('fromUnits is the exact inverse, trailing zeros trimmed', () => {
  assert.equal(fromUnits(5500000000000000000n), '5.5');
  assert.equal(fromUnits(5000000000000000000n), '5');
  assert.equal(fromUnits(0n), '0');
  assert.equal(fromUnits(toUnits('-3.5')), '-3.5');
});

test('fromUnits rejects a float instead of silently truncating', () => {
  assert.throws(() => fromUnits(5.5));
});

test('round trip is exact for a value floating-point multiplication would corrupt', () => {
  const huge = '1000000000000000000.123456789012345678';
  assert.equal(fromUnits(toUnits(huge)), huge);
});

test('fromFloat is faithful to what the float actually holds, unlike naive multiplication', () => {
  const value = 123456.789;
  const truth = value.toFixed(18);
  const viaModule = fromFloat(value);
  const viaNaive = BigInt(Math.round(value * 1e18));
  assert.equal(fromUnits(viaModule), truth);
  assert.notEqual(viaModule, viaNaive);
});

test('fromFloat rejects non-finite input', () => {
  assert.throws(() => fromFloat(NaN));
  assert.throws(() => fromFloat(Infinity));
});

test('fixedToUnits converts a Q128 fixed-point value straight to base units, exactly, no float in between', () => {
  assert.equal(fixedToUnits(SCALE), 1000000000000000000n); // exactly 1.0
  assert.equal(fixedToUnits(SCALE * 5n), 5000000000000000000n);
  assert.equal(fixedToUnits(0n), 0n);
});

test('fixedToUnits agrees with fromFloat within double precision — the two take genuinely different rounding paths (truncating BigInt division vs toFixed\'s round-to-nearest) below the 18th decimal, so this checks the value they both actually mean, not bit-for-bit string equality that far down', () => {
  const fixed = numberToFixed(123456.789);
  assert.equal(format(fixedToUnits(fixed), 8), format(fromFloat(123456.789), 8));
});

test('fixedToUnits rejects a non-bigint or a negative value', () => {
  assert.throws(() => fixedToUnits(5));
  assert.throws(() => fixedToUnits(-SCALE));
});

test('format trims to a readable number of decimals without padding false precision', () => {
  assert.equal(format(toUnits('5.123456789012345678')), '5.123456');
  assert.equal(format(toUnits('5')), '5');
  assert.equal(format(toUnits('5.123456789'), 2), '5.12');
});
