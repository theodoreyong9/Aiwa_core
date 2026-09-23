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
//
// Both require a real Ed25519 signature proving the real signer
// controls `domain` — exactly the same signerPubkey/signature-vs-owner
// discipline wallet.js's own 'transfer'/'split' already apply, mirrored
// here because adapt-event.js's toReducerEvent strips the outer event
// envelope's real `author` before any reducer ever sees it (by design,
// so reducers stay pure {id, parents, payload} functions — see its own
// header). Without this, 'claim'/'accrual' were the one pair of event
// types checked only against economic state, never against who
// actually signed the envelope: anyone could submit a real 'claim' or
// 'accrual' naming an unrelated domain, and it would be honored as if
// the real owner had submitted it. Not a theft — the resulting balance
// or claim still lands under, and is spendable only by, the named
// domain's real key — but it let anyone reset that domain's own
// patience clock (lastActionEpoch below) without consent, a real,
// narrow griefing vector against the T (patience) bonus in reward.js.

import { applyProgressionEvent, initialProgressionState } from './progression.js';
import { rewardFixed, domainAge } from './reward.js';
import { toUnits, fixedToUnits } from './units.js';
import { deriveId } from './identity.js';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function canonicalAccrualMessage({ domain, b, T, nonce, timestamp }) {
  return JSON.stringify({ domain, b, T: T ?? null, nonce, timestamp });
}

/** A real, domain-owner-signed commitment of additional capital `b` (and optionally `T`) to the domain's own position. */
export async function buildSignedAccrualEvent(fields, signerSeed, signerPubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const withMeta = { ...fields, nonce, timestamp: now };
  const signature = ed25519.sign(new TextEncoder().encode(canonicalAccrualMessage(withMeta)), signerSeed);
  return { ...withMeta, signerPubkey: toHex(signerPubkeyBytes), signature: toHex(signature) };
}

async function verifyAccrualAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { domain, b, T, nonce, timestamp, signerPubkey, signature } = event;
  if (typeof signerPubkey !== 'string' || typeof signature !== 'string') return false;
  if ((await deriveId(fromHex(signerPubkey))) !== domain) return false; // only the domain's real key can commit capital to its own position
  try {
    return ed25519.verify(fromHex(signature), new TextEncoder().encode(canonicalAccrualMessage({ domain, b, T, nonce, timestamp })), fromHex(signerPubkey));
  } catch {
    return false;
  }
}

function canonicalClaimMessage({ domain, amount, claimId, nonce, timestamp }) {
  return JSON.stringify({ domain, amount, claimId: claimId ?? null, nonce, timestamp });
}

/** A real, domain-owner-signed claim, moving `amount` from the domain's own accrued position into its real, spendable balance. */
export async function buildSignedClaimEvent(fields, signerSeed, signerPubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const withMeta = { ...fields, nonce, timestamp: now };
  const signature = ed25519.sign(new TextEncoder().encode(canonicalClaimMessage(withMeta)), signerSeed);
  return { ...withMeta, signerPubkey: toHex(signerPubkeyBytes), signature: toHex(signature) };
}

async function verifyClaimAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { domain, amount, claimId, nonce, timestamp, signerPubkey, signature } = event;
  if (typeof signerPubkey !== 'string' || typeof signature !== 'string') return false;
  if ((await deriveId(fromHex(signerPubkey))) !== domain) return false; // only the domain's real key can trigger its own claim
  try {
    return ed25519.verify(fromHex(signature), new TextEncoder().encode(canonicalClaimMessage({ domain, amount, claimId, nonce, timestamp })), fromHex(signerPubkey));
  } catch {
    return false;
  }
}

export function initialAccrualState() {
  return { progression: initialProgressionState(), positions: {}, balances: {}, usedNonces: {}, rejections: [] };
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
    const { domain, b, T, nonce, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (!Number.isFinite(b) || b < 0) return reject('b must be a finite number >= 0');
    if (typeof nonce !== 'string' || !nonce || typeof signerPubkey !== 'string' || typeof signature !== 'string') {
      return reject('malformed accrual payload');
    }
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyAccrualAuthorization(payload))) return reject('invalid signature: only the domain itself can commit capital to its own position');

    const currentEpoch = domainAge(state.progression, domain);
    const prior = state.positions[domain] ?? { b: 0, lastActionEpoch: currentEpoch, T: 0 };
    return {
      ...state,
      positions: { ...state.positions, [domain]: { b: prior.b + b, lastActionEpoch: currentEpoch, T: T ?? prior.T } },
      usedNonces: { ...state.usedNonces, [nonce]: true },
    };
  }

  if (payload.type === 'claim') {
    const { domain, nonce, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (!state.positions[domain]) return reject('no committed capital for this domain');
    if (typeof nonce !== 'string' || !nonce || typeof signerPubkey !== 'string' || typeof signature !== 'string') {
      return reject('malformed claim payload');
    }
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyClaimAuthorization(payload))) return reject('invalid signature: only the domain itself can claim its own accrued balance');

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
      usedNonces: { ...state.usedNonces, [nonce]: true },
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
