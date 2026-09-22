// 18-decimal fixed-point AIWA amounts. Always bigint smallest units,
// never a float. Conversion is string-based, never float multiplication.

import { SCALE } from './fixed-point-math.js';

export const DECIMALS = 18;
const UNIT = 10n ** BigInt(DECIMALS);

export function toUnits(amount, decimals = DECIMALS) {
  const str = typeof amount === 'string' ? amount.trim() : String(amount);
  if (!/^-?\d+(\.\d+)?$/.test(str)) {
    throw new Error(`Invalid amount: '${amount}'`);
  }
  const negative = str.startsWith('-');
  const unsigned = negative ? str.slice(1) : str;
  const [whole, frac = ''] = unsigned.split('.');
  if (frac.length > decimals) {
    throw new Error(`Too much precision: '${amount}' (max ${decimals} decimals)`);
  }
  const digits = `${whole}${frac.padEnd(decimals, '0')}`.replace(/^0+(?=\d)/, '');
  const magnitude = BigInt(digits === '' ? '0' : digits);
  return negative ? -magnitude : magnitude;
}

export function fromUnits(units, decimals = DECIMALS) {
  if (typeof units !== 'bigint') throw new Error(`Expected bigint, got ${typeof units}`);
  const negative = units < 0n;
  const abs = negative ? -units : units;
  const divisor = 10n ** BigInt(decimals);
  const whole = abs / divisor;
  const frac = (abs % divisor).toString().padStart(decimals, '0').replace(/0+$/, '');
  const body = frac.length > 0 ? `${whole}.${frac}` : whole.toString();
  return negative && abs > 0n ? `-${body}` : body;
}

// Converts a float (e.g. a reward formula output) via its own true
// fixed-decimal string, never via direct multiplication — that would
// silently overflow Number.MAX_SAFE_INTEGER for realistic values.
export function fromFloat(value, decimals = DECIMALS) {
  if (!Number.isFinite(value)) throw new Error(`Non-finite value: ${value}`);
  if (Math.abs(value) >= 1e21) throw new Error(`Value too large: ${value}`);
  return toUnits(value.toFixed(decimals), decimals);
}

// A Q128 fixed-point value (fixed-point-math.js's own Fixed — see
// reward.js's rewardFixed) straight to base units: one BigInt multiply,
// one truncating divide, never a float in between. This is what
// accrual.js's own real claim path uses instead of fromFloat(reward(...)):
// rewardFixed()'s whole point is a cross-runtime-reproducible BigInt
// result, and routing it through a JS Number first (fromFloat's own
// value.toFixed(decimals)) would reintroduce exactly the kind of
// non-guaranteed rounding step that exists to avoid.
export function fixedToUnits(fixedValue, decimals = DECIMALS) {
  if (typeof fixedValue !== 'bigint') throw new Error(`Expected bigint, got ${typeof fixedValue}`);
  if (fixedValue < 0n) throw new Error(`fixedToUnits: negative value ${fixedValue}`);
  return (fixedValue * 10n ** BigInt(decimals)) / SCALE;
}

export function format(units, maxDecimals = 6) {
  const full = fromUnits(units);
  const [whole, frac] = full.split('.');
  if (!frac) return whole;
  const trimmed = frac.slice(0, maxDecimals).replace(/0+$/, '');
  return trimmed.length > 0 ? `${whole}.${trimmed}` : whole;
}
