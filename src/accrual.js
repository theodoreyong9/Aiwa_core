// Composes progression.js and reward.js into a real position per
// domain: committed capital b, and the epoch of the domain's own last
// action (an accrual or a claim) — never a caller-supplied value,
// always derived from the domain's own real, independently folded
// progression, exactly the "recompute, don't trust" discipline this
// project applies everywhere else. A caller providing its own
// reference epoch would let anyone claim t=currentEpoch forever.
//
// t (time since the last action) resets on every accrual or claim —
// the reward formula rewards patience since you last touched your own
// position, not since genesis. A (domainAge, the denominator
// reference) never resets — it is the domain's own total progression,
// regardless of how often it claims.
//
// 'accrual': { domain, b } — commits additional capital, adds to any
// already-committed b, resets the patience clock.
// 'claim': { domain, amount, T } — computes what is currently
// claimable from the real position, debits up to that amount into a
// real bigint balance, resets the patience clock.

import { applyProgressionEvent, initialProgressionState } from './progression.js';
import { rewardFixed, domainAge } from './reward.js';
import { toUnits, fixedToUnits } from './units.js';

export function initialAccrualState() {
  return { progression: initialProgressionState(), positions: {}, balances: {}, rejections: [] };
}

// Straight from rewardFixed()'s own reproducible Q128 BigInt to real
// on-chain base units — no JS Number in between. This is the actual
// point of rewardFixed existing: a claim is a real balance credit, and
// routing it through a float first (the old reward()+fromFloat path)
// would reintroduce the one non-reproducible step a future Rust node
// would disagree with a JS one on.
function currentlyClaimableUnits(rewardParams, state, domain) {
  const position = state.positions[domain];
  if (!position) return 0n;
  const currentEpoch = domainAge(state.progression, domain);
  const t = Math.max(0, currentEpoch - position.lastActionEpoch);
  const fixed = rewardFixed(position.b, t, currentEpoch, position.T ?? 0, rewardParams);
  return fixed === null ? 0n : fixedToUnits(fixed);
}

export async function applyAccrualEvent(rewardParams, state, event, verifyFn) {
  const payload = event.payload;
  if (!payload || typeof payload.type !== 'string') return state;

  if (payload.type === 'progression') {
    return { ...state, progression: await applyProgressionEvent(state.progression, event, verifyFn) };
  }

  if (payload.type === 'accrual') {
    const { domain, b, T } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (!Number.isFinite(b) || b < 0) return reject('b must be a finite number >= 0');

    const currentEpoch = domainAge(state.progression, domain);
    const prior = state.positions[domain] ?? { b: 0, lastActionEpoch: currentEpoch, T: 0 };
    return { ...state, positions: { ...state.positions, [domain]: { b: prior.b + b, lastActionEpoch: currentEpoch, T: T ?? prior.T } } };
  }

  if (payload.type === 'claim') {
    const { domain } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (!state.positions[domain]) return reject('no committed capital for this domain');

    const claimableUnits = currentlyClaimableUnits(rewardParams, state, domain);

    let amount;
    try {
      amount = toUnits(payload.amount);
    } catch {
      return reject('malformed amount');
    }
    if (!(amount > 0n)) return reject('amount must be positive');
    if (amount > claimableUnits) return reject(`insufficient claimable: has ${claimableUnits}, tried to claim ${amount}`);

    const currentEpoch = domainAge(state.progression, domain);
    const currentBalance = state.balances[domain] ?? 0n;
    return {
      ...state,
      positions: { ...state.positions, [domain]: { ...state.positions[domain], lastActionEpoch: currentEpoch } },
      balances: { ...state.balances, [domain]: currentBalance + amount },
    };
  }

  return state;
}

export async function materializeAccrual(rewardParams, orderedEvents, verifyFn) {
  let state = initialAccrualState();
  for (const event of orderedEvents) state = await applyAccrualEvent(rewardParams, state, event, verifyFn);
  return state;
}

export function claimableNow(rewardParams, state, domain) {
  return currentlyClaimableUnits(rewardParams, state, domain);
}
