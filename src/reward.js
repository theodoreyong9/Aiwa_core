// r(b, q, qTotal, T) = (b * q^alpha) / [ln(qTotal^(beta*(1-T)) + C)]^gamma
//
// qTotal is this domain's OWN progression epoch count, never a value
// shared across domains — requiring a shared reference would
// reintroduce cross-domain synchronization, which this system is
// built to avoid.
//
// Computed in Q128 fixed-point BigInt (fixed-point-math.js), not
// Math.log/Math.pow — reward() output funds a real, on-chain AIWA claim
// (see accrual.js), and IEEE 754 never guarantees Math.log/Math.pow agree
// bit-for-bit between two different runtimes the way +,-,*,/ do. See
// fixed-point-math.js's own header for the full reasoning. rewardFixed()
// below is the reproducible core; reward() is a plain-Number convenience
// wrapper, unchanged in signature and behavior.

import { numberToFixed, fixedToNumber, mulFixed, divFixed, powFixed, lnFixed, SCALE } from './fixed-point-math.js';

export class RewardError extends Error {}

const CAP_FIXED = numberToFixed(1e12);

// The reproducible core: identical inputs (as Numbers, converted to Fixed
// via the exact IEEE-754 decomposition in fixed-point-math.js) yield an
// identical Fixed BigInt in any correct implementation, JS or otherwise —
// unlike reward()'s own final Fixed-to-Number step, which is a JS-only
// convenience and isn't part of that guarantee. Returns null exactly
// where reward() would return 0, so callers that want the raw units
// (accrual.js) don't have to duplicate reward()'s own gating logic.
export function rewardFixed(b, q, qTotal, patienceRate, { alpha, beta, gamma, C, minQ }) {
  if (!Number.isFinite(b) || b < 0) throw new RewardError(`b must be >= 0, got ${b}`);
  if (!Number.isFinite(q) || q < 0) throw new RewardError(`q must be >= 0, got ${q}`);
  if (!Number.isFinite(qTotal) || qTotal < 0) throw new RewardError(`qTotal must be >= 0, got ${qTotal}`);
  if (![alpha, beta, gamma, C, minQ].every(Number.isFinite)) {
    throw new RewardError('alpha, beta, gamma, C, minQ must all be finite');
  }

  if (q < minQ) return null;

  const T = Math.min(Math.max(patienceRate, 0), 0.4);
  const effQ = Math.max(1, q);
  const effQTotal = Math.max(1, qTotal);

  const bFixed = numberToFixed(b);
  const alphaFixed = numberToFixed(alpha);
  const betaFixed = numberToFixed(beta);
  const gammaFixed = numberToFixed(gamma);
  const cFixed = numberToFixed(C);
  const effQFixed = numberToFixed(effQ);
  const effQTotalFixed = numberToFixed(effQTotal);
  const oneMinusTFixed = SCALE - numberToFixed(T); // exact: 1 is exactly SCALE in Q128

  const numerator = mulFixed(powFixed(effQFixed, alphaFixed), bFixed);
  const exponent = mulFixed(betaFixed, oneMinusTFixed);
  const inner = powFixed(effQTotalFixed, exponent) + cFixed;
  if (inner <= SCALE) return null; // inner <= 1

  const lnInner = lnFixed(inner); // > 0, guaranteed by the inner <= SCALE check above
  const denominator = powFixed(lnInner, gammaFixed);
  if (denominator <= 0n) return null; // BigInt has no NaN/Infinity to also guard against here

  const r = divFixed(numerator, denominator);
  return (r < 0n || r > CAP_FIXED) ? null : r;
}

export function reward(b, q, qTotal, patienceRate, params) {
  const fixed = rewardFixed(b, q, qTotal, patienceRate, params);
  return fixed === null ? 0 : fixedToNumber(fixed);
}

export function elapsedEpochs(progressionState, domain, q0) {
  const currentEpoch = progressionState.domains[domain]?.epoch ?? 0;
  return Math.max(0, currentEpoch - q0);
}

export function domainAge(progressionState, domain) {
  return progressionState.domains[domain]?.epoch ?? 0;
}
