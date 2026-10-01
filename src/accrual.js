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
// "Last action" mining (the same shape as YourMine's own): the position is
// what the domain's LAST action left it.
// 'accrual': { domain, b, T } — a burn's commitment. It REPLACES the
// position: b is the capital that now mines (b = burned x (1 - T)), T the
// patience rate chosen at this burn for what follows. Before replacing, the
// claimable accrued so far is PAID (an automatic claim, credited to the
// domain's balance): a new burn never forfeits what the previous one earned.
// It resets the patience clock.
// 'claim': { domain, amount } — computes what is currently claimable from
// the real position, debits up to that amount into a real bigint balance,
// resets the patience clock. T stays the one chosen at the last burn.
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

import { verifyBurnRecordFor } from './burn-record.js';
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

// Same one-time delegation object wallet.js's own issueDelegation
// produces ({delegate, from, ownerPubkey, delegationSignature}),
// reused here exactly like wallet.js's own delegated-transfer/
// delegated-split/delegated-voucher-redeem: a channel's session key can
// trigger a claim for its real owner (delegation.from) without the
// owner's root key signing the claim itself. `canonicalDelegationMessage`
// is duplicated (not imported) from wallet.js to avoid a circular
// import — wallet.js already imports from this file.
function canonicalDelegationMessage({ delegate, from }) {
  return JSON.stringify({ delegate, from });
}

function canonicalDelegatedClaimMessage({ domain, amount, claimId, delegate, nonce, timestamp }) {
  return JSON.stringify({ domain, amount, claimId: claimId ?? null, delegate, nonce, timestamp });
}

/** One real, delegate-signed claim, reusing an already-issued real delegation, landing the claimed value under the real owner's domain (delegation.from) — never needs the owner's own key again. */
export async function buildSignedDelegatedClaimEvent(delegation, fields, delegateSeed, delegatePubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { claimId, amount } = fields;
  const withMeta = { domain: delegation.from, amount, claimId, delegate: delegation.delegate, nonce, timestamp: now };
  const signature = ed25519.sign(new TextEncoder().encode(canonicalDelegatedClaimMessage(withMeta)), delegateSeed);
  return {
    ...withMeta,
    ownerPubkey: delegation.ownerPubkey,
    delegationSignature: delegation.delegationSignature,
    signerPubkey: toHex(delegatePubkeyBytes),
    signature: toHex(signature),
  };
}

async function verifyDelegatedClaimAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { domain, amount, claimId, delegate, nonce, timestamp, ownerPubkey, delegationSignature, signerPubkey, signature } = event;

  if ((await deriveId(fromHex(ownerPubkey))) !== domain) return false; // the claim's own real domain must really derive from the embedded owner pubkey
  if (toHex(fromHex(signerPubkey)) !== delegate) return false; // the claim's own real signer must be exactly the delegated key, not anyone else

  let delegationValid;
  try {
    delegationValid = ed25519.verify(fromHex(delegationSignature), new TextEncoder().encode(canonicalDelegationMessage({ delegate, from: domain })), fromHex(ownerPubkey));
  } catch {
    return false;
  }
  if (!delegationValid) return false; // the real owner never actually authorized this delegate

  let claimSigValid;
  try {
    claimSigValid = ed25519.verify(fromHex(signature), new TextEncoder().encode(canonicalDelegatedClaimMessage({ domain, amount, claimId, delegate, nonce, timestamp })), fromHex(signerPubkey));
  } catch {
    return false;
  }
  return claimSigValid; // the delegate really signed THIS specific claim, not a replay of a differently-addressed one
}

// burns: what this READER has confirmed about burns. `records` is seeded by the caller (signature -> the
// record fetchBurnRecord returned: the reader's own check against Solana); `covered` (domain -> lamports) and
// `used` (signature -> true) are derived by folding 'burn-record' events. A reducer never reaches Solana: what
// it may count is exactly what the reader put in `records`.
// `consumed` (domain -> lamports): what the domain's commitments have used of what it burned. A burn backs a
// commitment once: it is spent by it, even though the next commitment replaces the position.
export function initialBurnsState() {
  return { records: {}, covered: {}, used: {}, consumed: {} };
}

export function initialAccrualState() {
  return { progression: initialProgressionState(), positions: {}, balances: {}, usedNonces: {}, rejections: [], burns: initialBurnsState() };
}

const LAMPORTS_PER_UNIT = 1_000_000_000;
export const MAX_PATIENCE_RATE = 0.4;

/**
 * What a commitment of capital `b` at patience rate `T` costs, in lamports of confirmed burn: the capital that
 * counts is what is left of the burn after T of it is destroyed without counting — b = burned x (1 - T), so
 * burned = ceil(b / (1 - T)). T is therefore a real choice: a larger T makes the reward curve more generous, and
 * costs that share of the burn. (There is no recipient of that share: it is destroyed.)
 */
export function commitmentPriceLamports(b, T = 0) {
  const lamports = Math.round(b * LAMPORTS_PER_UNIT);
  if (!T) return lamports;
  return Math.ceil(lamports / (1 - T) - 1e-6);
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

    const rate = T === undefined || T === null ? 0 : T;
    if (!Number.isFinite(rate) || rate < 0 || rate > MAX_PATIENCE_RATE) return reject(`T must be between 0 and ${MAX_PATIENCE_RATE}`);

    const currentEpoch = domainAge(state.progression, domain);
    const price = commitmentPriceLamports(b, rate);
    const consumed = state.burns?.consumed?.[domain] ?? 0;
    // The genesis commitment (yellow paper §8): capital is what a burn covers. What this domain's commitments have
    // used, plus this one's price, may not exceed what burns THIS READER has confirmed for it (see 'burn-record'
    // below). The deployment may opt out explicitly — `rewardParams.commitmentBacking: 'none'` — for tests, demos,
    // private economies; leaving it out means mandatory.
    if (rewardParams?.commitmentBacking !== 'none') {
      const covered = state.burns?.covered?.[domain] ?? 0;
      if (consumed + price > covered) {
        return reject(`commitment of ${b} at T=${rate} is not covered by a confirmed burn: it costs ${price} lamports, ${covered - consumed} are left (${covered} confirmed for this domain, ${consumed} already used)`);
      }
    }
    // The claimable accrued so far is paid before the position is replaced.
    const pending = currentlyClaimableUnits(rewardParams, state, domain);
    const balance = state.balances[domain] ?? 0n;
    return {
      ...state,
      positions: { ...state.positions, [domain]: { b, lastActionEpoch: currentEpoch, T: rate } },
      balances: pending > 0n ? { ...state.balances, [domain]: balance + pending } : state.balances,
      burns: { ...(state.burns ?? initialBurnsState()), consumed: { ...(state.burns?.consumed ?? {}), [domain]: consumed + price } },
      usedNonces: { ...state.usedNonces, [nonce]: true },
    };
  }

  // A domain pointing at a burn it made: { type: 'burn-record', domain, signature } — the Solana transaction
  // signature, nothing else. What the burn was worth is NOT read from the event (anyone can write anything in
  // an event): it is read from the record this reader fetched from Solana itself (state.burns.records), and the
  // burn counts for `domain` only if that record is a finalized burn paid by the domain's own key. One
  // signature counts once.
  if (payload.type === 'burn-record') {
    const { domain, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (typeof signature !== 'string' || !signature) return reject('missing transaction signature');
    const burns = state.burns ?? initialBurnsState();
    if (burns.used[signature]) return reject(`burn ${signature} already counted`);
    const record = burns.records[signature];
    if (!record) return reject(`burn ${signature} is not confirmed by this reader (no finalized transaction record)`);
    const check = await verifyBurnRecordFor(domain, record);
    if (!check.valid) return reject(check.reason);
    return {
      ...state,
      burns: {
        ...burns,
        covered: { ...burns.covered, [domain]: (burns.covered[domain] ?? 0) + record.incineratorBalanceDeltaLamports },
        used: { ...burns.used, [signature]: true },
      },
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

  if (payload.type === 'delegated-claim') {
    const { domain, nonce, delegate, ownerPubkey, delegationSignature, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, domain: domain ?? null, reason }] });
    if (typeof domain !== 'string' || !domain) return reject('missing domain');
    if (!state.positions[domain]) return reject('no committed capital for this domain');
    if (![nonce, delegate, ownerPubkey, delegationSignature, signerPubkey, signature].every((v) => typeof v === 'string' && v)) {
      return reject('malformed delegated-claim payload');
    }
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyDelegatedClaimAuthorization(payload))) return reject('invalid delegated signature');

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

/**
 * `walletState` with the burn records a reader has confirmed put where the reducer looks for them
 * (accrual.burns.records: signature -> fetchBurnRecord's result). Fold 'burn-record' events on top of the state this
 * returns. Records are added to, never replaced: what was confirmed stays confirmed.
 */
export function withConfirmedBurns(walletState, records) {
  const accrual = walletState.accrual ?? initialAccrualState();
  const burns = accrual.burns ?? initialBurnsState();
  return { ...walletState, accrual: { ...accrual, burns: { ...burns, records: { ...burns.records, ...records } } } };
}
