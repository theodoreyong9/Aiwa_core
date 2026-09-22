// A real, deterministic replacement for Math.log / Math.exp / (fractional)
// Math.pow, built from nothing but BigInt +, -, *, and truncating-toward-zero
// / — the four operations ECMAScript's own spec (and Rust's num-bigint,
// mirroring native integer semantics) both guarantee bit-for-bit identical
// across any two conforming implementations. Math.log/Math.pow carry no
// such guarantee: IEEE 754 only pins down correct rounding for +,-,*,/,
// never for transcendental functions, so two different libm builds (glibc
// vs Rust's own) can legitimately disagree on the last bit. Since reward.js
// feeds a real, on-chain AIWA amount (see accrual.js), that last-bit
// disagreement is a real consensus risk between a JS node and a future
// Rust one — this module closes it.
//
// Representation: Q128 binary fixed point. A "Fixed" value is a BigInt
// equal to realValue * 2^FRAC_BITS — chosen (not decimal/10^n) because
// range reduction by powers of 2 is *exact* (a bit shift, no rounding),
// which is exactly what makes ln/exp reproducible rather than merely
// close. FRAC_BITS=128 gives ~38 decimal digits of resolution, comfortably
// above the 18 decimals AIWA's own base units (units.js) ever need.
//
// One rule enforced everywhere in this file: never bit-shift a negative
// BigInt. JS defines BigInt >> as a floor (arithmetic) shift; whether
// num-bigint's BigInt matches that for negative operands is genuinely
// unclear from its docs, and this project doesn't trust what it hasn't
// verified. Every shift below operates on a value already known
// non-negative (magnitudes, or values proven positive by the real math,
// like exp()'s result) — sign is tracked and reapplied separately instead.

export class FixedPointError extends Error {}

export const FRAC_BITS = 128n;
export const SCALE = 1n << FRAC_BITS;

// Fixed * Fixed = Fixed needs one /SCALE to undo the double-scaling;
// Fixed / Fixed = Fixed needs one *SCALE first to keep a whole-number
// result. Both divisions truncate toward zero — the one rounding choice
// this whole module makes, applied identically everywhere, so the
// specific choice matters far less than its consistency does.
export function mulFixed(a, b) {
  return (a * b) / SCALE;
}

export function divFixed(a, b) {
  if (b === 0n) throw new FixedPointError('divFixed: division by zero');
  return (a * SCALE) / b;
}

// Bit length of a non-negative BigInt — 0 for 0n, otherwise the position
// (1-indexed count) of its highest set bit. Shifts only non-negative x, so
// this is exact and unambiguous in both languages regardless of how each
// one's BigInt happens to be stored internally.
export function bitLengthNonNeg(n) {
  if (n < 0n) throw new FixedPointError(`bitLengthNonNeg: negative input ${n}`);
  let bits = 0n;
  let x = n;
  while (x > 0n) {
    x >>= 1n;
    bits += 1n;
  }
  return bits;
}

// Exact IEEE 754 double decomposition (sign, biased exponent, mantissa),
// via the standard bit layout every conformant implementation shares —
// JS via a DataView read, Rust via f64::to_bits() — rather than via
// float multiplication, which would reintroduce the very kind of
// implementation-defined rounding this module exists to avoid. Exact
// (no precision lost) for any input whose real value fits within
// FRAC_BITS of the binary point, which every realistic reward.js input
// (epoch counts, committed capital, the small protocol constants) does.
export function numberToFixed(x) {
  if (!Number.isFinite(x)) throw new FixedPointError(`numberToFixed: not finite: ${x}`);
  if (x === 0) return 0n;

  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setFloat64(0, x, false); // false = big-endian byte order, so bit 63 really is the sign bit below
  const bits = view.getBigUint64(0, false);

  const sign = (bits >> 63n) & 1n;
  const rawExp = (bits >> 52n) & 0x7ffn;
  const rawMantissa = bits & 0xfffffffffffffn;

  let exp2, mantissa;
  if (rawExp === 0n) {
    // Subnormal: real value = mantissa * 2^-1074, no implicit leading bit.
    exp2 = -1074n;
    mantissa = rawMantissa;
  } else {
    // Normal: real value = (2^52 + mantissa) * 2^(rawExp-1023-52).
    exp2 = rawExp - 1023n - 52n;
    mantissa = rawMantissa | (1n << 52n);
  }

  const shift = exp2 + FRAC_BITS;
  const magnitude = shift >= 0n ? (mantissa << shift) : (mantissa >> -shift);
  return sign === 1n ? -magnitude : magnitude;
}

// Fixed -> Number, for convenience at the JS-only boundary (existing
// callers that still want a plain number back). Deliberately NOT part of
// the cross-runtime guarantee the rest of this module provides — BigInt-
// to-double conversion has its own rounding step this function doesn't
// try to pin down further. Anything that must match Rust bit-for-bit
// should stay in Fixed (or convert straight to decimal units — see
// units.js) rather than round-tripping through this.
export function fixedToNumber(f) {
  const sign = f < 0n ? -1 : 1;
  const abs = f < 0n ? -f : f;
  const intPart = abs >> FRAC_BITS;
  const fracPart = abs & (SCALE - 1n);
  return sign * (Number(intPart) + Number(fracPart) / Number(SCALE));
}

// atanh series: 2*atanh(y) = 2*(y + y^3/3 + y^5/5 + ...), for 0 <= y <=
// 1/3 — exactly the range lnFixed's own range reduction below produces.
// A fixed, hardcoded term count, never "until the term is small enough":
// that stopping rule would itself depend on the runtime's own arithmetic,
// the exact non-determinism this module is built to avoid. 60 terms at
// |y|<=1/3 pushes the largest dropped term below 3^-121, comfortably
// inside FRAC_BITS' own ~2^-128 resolution.
const LN_SERIES_TERMS = 60n;

function lnSeriesFromY(y) {
  const y2 = mulFixed(y, y);
  let term = y;
  let denom = 1n;
  let sum = 0n;
  for (let i = 0n; i < LN_SERIES_TERMS; i++) {
    sum += term / denom;
    term = mulFixed(term, y2);
    denom += 2n;
  }
  return sum * 2n;
}

// ln(2), derived from the identical series above (y=1/3 gives t=2
// exactly: (1+1/3)/(1-1/3) = 2) rather than transcribed as a decimal
// literal — one less place a copy-paste digit error could hide, and the
// same reasoning this module applies everywhere else ("recompute, don't
// trust a hand-carried value").
const ONE_THIRD = SCALE / 3n;
export const LN2 = lnSeriesFromY(ONE_THIRD);

// ln(x) for x > 0 (Fixed). Range-reduces x = t * 2^k with t's real value
// in [1, 2) — an exact bit shift, not an approximation — then
// ln(realValue) = k*ln(2) + ln(t), with ln(t) via the atanh series above
// on y = (t-1)/(t+1), which stays in [0, 1/3] for t in [1,2) by
// construction, exactly the domain the series is built for.
export function lnFixed(x) {
  if (x <= 0n) throw new FixedPointError(`lnFixed: domain error, x must be > 0, got ${x}`);
  const k = bitLengthNonNeg(x) - 1n - FRAC_BITS;
  const t = k >= 0n ? (x >> k) : (x << -k);
  const y = divFixed(t - SCALE, t + SCALE);
  const lnT = lnSeriesFromY(y);
  return k * LN2 + lnT;
}

// exp(r) Taylor series: 1 + r + r^2/2! + ... — a fixed term count again,
// sized for the |r| <= ln(2)/2 ≈ 0.3466 range expFixed's own reduction
// below guarantees. 40 terms pushes the largest dropped term below
// 0.3466^41/41!.
const EXP_SERIES_TERMS = 40n;

function expSeriesFromR(r) {
  let term = SCALE;
  let sum = SCALE;
  for (let i = 1n; i <= EXP_SERIES_TERMS; i++) {
    term = mulFixed(term, r) / i;
    sum += term;
  }
  return sum;
}

// Round n/d to the nearest integer (ties away from zero), d > 0, using
// only truncating division on non-negative operands — sidesteps any
// question of how either language's BigInt truncates a *negative*
// division, by never asking it to.
function divRoundNearest(n, d) {
  const sign = n < 0n ? -1n : 1n;
  const absN = n < 0n ? -n : n;
  return sign * ((absN + d / 2n) / d);
}

// exp(x) for any signed Fixed x. Range-reduces x = k*ln(2) + r with
// |r| <= ln(2)/2 (round-to-nearest k), so exp(x) = 2^k * exp(r) — the
// 2^k factor applied as an exact bit shift (always on the series' own
// result, which the real math guarantees is positive for this bounded
// r, so the shift is always on a non-negative operand).
export function expFixed(x) {
  const k = divRoundNearest(x, LN2);
  const r = x - k * LN2;
  const series = expSeriesFromR(r);
  return k >= 0n ? (series << k) : (series >> -k);
}

// a^b for a > 0 (Fixed), b any signed Fixed exponent — exp(b * ln(a)),
// the identical identity Math.pow itself relies on internally for
// non-integer exponents, just built from the two reproducible pieces
// above instead of the platform's own libm.
export function powFixed(a, b) {
  if (a <= 0n) throw new FixedPointError(`powFixed: domain error, a must be > 0, got ${a}`);
  return expFixed(mulFixed(b, lnFixed(a)));
}
