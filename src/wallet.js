// Composes accrual.js and conservation.js into one materialized wallet
// state. A 'claim' event debits the accrued balance AND creates the
// matching spendable Conservation claim in the same pass — both
// checked before either is applied, so they can never drift apart.
//
// 'transfer' and 'split' require a real Ed25519 signature — moving or
// dividing a claim must prove control over it.

import { applyAccrualEvent, initialAccrualState, claimableNow } from './accrual.js';
import { initialConservationState, issueClaim, transfer, splitClaim, identityDerivation } from './conservation.js';
import { deriveId } from './identity.js';
import { toUnits } from './units.js';

const derivations = { identity: identityDerivation };

export function initialWalletState() {
  return { accrual: initialAccrualState(), conservation: initialConservationState(), usedNonces: {}, rejections: [] };
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function canonicalTransferMessage({ claimId, from, to, nonce, timestamp }) {
  return JSON.stringify({ claimId, from, to, nonce, timestamp });
}

export async function buildSignedTransferEvent(fields, signerSeed, signerPubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const withMeta = { ...fields, nonce, timestamp: now };
  const message = new TextEncoder().encode(canonicalTransferMessage(withMeta));
  const signature = ed25519.sign(message, signerSeed);
  return { ...withMeta, signerPubkey: toHex(signerPubkeyBytes), signature: toHex(signature) };
}

async function verifyTransferAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const message = new TextEncoder().encode(canonicalTransferMessage(event));
  let sigValid;
  try {
    sigValid = ed25519.verify(fromHex(event.signature), message, fromHex(event.signerPubkey));
  } catch {
    return false;
  }
  if (!sigValid) return false;
  return (await deriveId(fromHex(event.signerPubkey))) === event.from;
}

function canonicalSplitMessage({ claimId, owner, firstAmount, firstId, secondId, nonce, timestamp }) {
  return JSON.stringify({ claimId, owner, firstAmount, firstId, secondId, nonce, timestamp });
}

// Real delegated authorization: "sign once, then click as many times
// as you want" without ever moving funds into a separate, pre-funded
// account first. Two REAL, separate signatures compose:
//
// - The real, one-time DELEGATION itself: the real claim owner signs
//   `canonicalDelegationMessage({delegate, from})` — no amount, no
//   expiry, by design (a deployment wanting either can layer it into
//   its own contractVerifiers via 'contract-payout' instead of forcing
//   it on every caller here). This is the one signature a slower,
//   more-trusted context (the owner's own root key) ever has to
//   produce for this whole channel.
// - Each real, individual transfer: signed by the DELEGATE's own key,
//   over `canonicalDelegatedTransferMessage(...)` — cheap, repeatable,
//   never touches the owner's root key again.
//
// A transfer's actual real signer (verified via signerPubkey, exactly
// like an ordinary transfer) is the delegate, NOT the claim's real
// owner — `from` is instead proven via a SEPARATE, embedded proof:
// ownerPubkey really derives to `from`, AND the embedded delegation
// signature really verifies against that same ownerPubkey. Skipping
// either check would let anyone claim an arbitrary `from` while
// signing as themselves — the identical forgery class
// aiwa-lib's own contract.js documents for `signedAction`.
function canonicalDelegationMessage({ delegate, from }) {
  return JSON.stringify({ delegate, from });
}

function canonicalDelegatedTransferMessage({ claimId, from, to, delegate, nonce, timestamp }) {
  return JSON.stringify({ claimId, from, to, delegate, nonce, timestamp });
}

/** The real, one-time delegation signature — computed once by the real claim owner, then reused, unchanged, on every subsequent buildSignedDelegatedTransferEvent() call for this same delegate. */
export async function issueDelegation(ownerSeed, ownerPubkeyBytes, delegatePubkeyBytes) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const delegate = toHex(delegatePubkeyBytes);
  const from = await deriveId(ownerPubkeyBytes);
  const signature = ed25519.sign(new TextEncoder().encode(canonicalDelegationMessage({ delegate, from })), ownerSeed);
  return { delegate, from, ownerPubkey: toHex(ownerPubkeyBytes), delegationSignature: toHex(signature) };
}

/** One real, delegate-signed transfer, reusing an already-issued real delegation (see issueDelegation) — this is the repeatable "click" side; it never needs the owner's own key again. */
export async function buildSignedDelegatedTransferEvent(delegation, fields, delegateSeed, delegatePubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { claimId, to } = fields;
  const withMeta = { claimId, from: delegation.from, to, delegate: delegation.delegate, nonce, timestamp: now };
  const signature = ed25519.sign(new TextEncoder().encode(canonicalDelegatedTransferMessage(withMeta)), delegateSeed);
  return {
    ...withMeta,
    ownerPubkey: delegation.ownerPubkey,
    delegationSignature: delegation.delegationSignature,
    signerPubkey: toHex(delegatePubkeyBytes),
    signature: toHex(signature),
  };
}

async function verifyDelegatedTransferAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { claimId, from, to, delegate, nonce, timestamp, ownerPubkey, delegationSignature, signerPubkey, signature } = event;

  if ((await deriveId(fromHex(ownerPubkey))) !== from) return false; // the claimed owner must really derive from the embedded owner pubkey
  if (toHex(fromHex(signerPubkey)) !== delegate) return false; // the transfer's own real signer must be exactly the delegated key, not anyone else

  let delegationValid;
  try {
    delegationValid = ed25519.verify(fromHex(delegationSignature), new TextEncoder().encode(canonicalDelegationMessage({ delegate, from })), fromHex(ownerPubkey));
  } catch {
    return false;
  }
  if (!delegationValid) return false; // the real owner never actually authorized this delegate

  let transferSigValid;
  try {
    transferSigValid = ed25519.verify(fromHex(signature), new TextEncoder().encode(canonicalDelegatedTransferMessage({ claimId, from, to, delegate, nonce, timestamp })), fromHex(signerPubkey));
  } catch {
    return false;
  }
  return transferSigValid; // the delegate really signed THIS specific transfer, not a replay of a differently-addressed one
}

export async function buildSignedSplitEvent(fields, signerSeed, signerPubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const withMeta = { ...fields, nonce, timestamp: now };
  const message = new TextEncoder().encode(canonicalSplitMessage(withMeta));
  const signature = ed25519.sign(message, signerSeed);
  return { ...withMeta, signerPubkey: toHex(signerPubkeyBytes), signature: toHex(signature) };
}

async function verifySplitAuthorization(event) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const message = new TextEncoder().encode(canonicalSplitMessage(event));
  let sigValid;
  try {
    sigValid = ed25519.verify(fromHex(event.signature), message, fromHex(event.signerPubkey));
  } catch {
    return false;
  }
  if (!sigValid) return false;
  return (await deriveId(fromHex(event.signerPubkey))) === event.owner;
}

export async function applyWalletEvent(rewardParams, state, event, verifyFn, contractVerifiers = {}) {
  const payload = event.payload;
  if (!payload || typeof payload.type !== 'string') return state;

  if (payload.type === 'progression' || payload.type === 'accrual') {
    return { ...state, accrual: await applyAccrualEvent(rewardParams, state.accrual, event, verifyFn) };
  }

  if (payload.type === 'claim') {
    const { domain, claimId } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, reason }] });
    if (typeof claimId !== 'string' || !claimId) return reject('missing claimId');
    if (state.conservation.claims[claimId]) return reject(`claim id already exists: ${claimId}`);

    const newAccrual = await applyAccrualEvent(rewardParams, state.accrual, event, verifyFn);
    const before = state.accrual.balances[domain] ?? 0n;
    const after = newAccrual.balances[domain] ?? 0n;
    if (after === before) return { ...state, accrual: newAccrual };

    const amount = toUnits(payload.amount);
    const conservation = issueClaim(state.conservation, { id: claimId, kind: 'AIWA', amount, owner: domain });
    return { ...state, accrual: newAccrual, conservation };
  }

  if (payload.type === 'transfer') {
    const { claimId, from, to, nonce, timestamp, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, reason }] });
    if (![claimId, from, to, nonce, signerPubkey, signature].every((v) => typeof v === 'string' && v)) return reject('malformed transfer payload');
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyTransferAuthorization({ claimId, from, to, nonce, timestamp, signerPubkey, signature }))) return reject('invalid signature');
    try {
      const { state: conservation } = transfer(state.conservation, { claimId, from, to, n: 0, derivation: 'identity' }, derivations);
      return { ...state, conservation, usedNonces: { ...state.usedNonces, [nonce]: true } };
    } catch (e) {
      return reject(e.message);
    }
  }

  // "Sign once, then click as many times as you want": a real, one-time
  // delegation (see issueDelegation) lets a real delegate key move the
  // owner's already-owned claims repeatedly, without the owner's own
  // root key signing more than once. No amount cap, no expiry — a real
  // deployment wanting either layers it into contractVerifiers via
  // 'contract-payout' instead of forcing it on every caller here.
  if (payload.type === 'delegated-transfer') {
    const { claimId, from, to, delegate, nonce, timestamp, ownerPubkey, delegationSignature, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, reason }] });
    if (![claimId, from, to, delegate, nonce, ownerPubkey, delegationSignature, signerPubkey, signature].every((v) => typeof v === 'string' && v)) {
      return reject('malformed delegated-transfer payload');
    }
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyDelegatedTransferAuthorization({ claimId, from, to, delegate, nonce, timestamp, ownerPubkey, delegationSignature, signerPubkey, signature }))) {
      return reject('invalid delegated signature');
    }
    try {
      const { state: conservation } = transfer(state.conservation, { claimId, from, to, n: 0, derivation: 'identity' }, derivations);
      return { ...state, conservation, usedNonces: { ...state.usedNonces, [nonce]: true } };
    } catch (e) {
      return reject(e.message);
    }
  }

  if (payload.type === 'split') {
    const { claimId, owner, firstId, secondId, nonce, timestamp, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, reason }] });
    if (![claimId, owner, firstId, secondId, nonce, signerPubkey, signature].every((v) => typeof v === 'string' && v)) return reject('malformed split payload');
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifySplitAuthorization({ claimId, owner, firstAmount: payload.firstAmount, firstId, secondId, nonce, timestamp, signerPubkey, signature }))) return reject('invalid signature');
    try {
      const firstAmount = toUnits(payload.firstAmount);
      const conservation = splitClaim(state.conservation, { claimId, firstAmount, firstId, secondId });
      return { ...state, conservation, usedNonces: { ...state.usedNonces, [nonce]: true } };
    } catch (e) {
      return reject(e.message);
    }
  }

  // generous-transfer.js's own external contract — the one, narrow,
  // explicitly justified exception to "never touch the core protocol
  // for a contract". A real, generic extension point — never a
  // per-contract case added here again. Any contract wanting to move
  // real, already-owned AIWA conditionally exposes its own real
  // `verifyPayout(payload)`, registered by the application under its
  // own real `contractId` (never wallet.js's own source) in
  // `contractVerifiers`. wallet.js only ever guarantees the one thing
  // every such contract needs and can safely share: the pre-signed
  // transfer's own signature is real and valid, checked identically to
  // an ordinary transfer, before ever asking the contract's own logic
  // whether its own conditions were genuinely met.
  if (payload.type === 'contract-payout') {
    const { contractId, claimId, from, to, nonce, timestamp, signerPubkey, signature } = payload;
    const reject = (reason) => ({ ...state, rejections: [...state.rejections, { eventId: event.id, reason }] });
    if (typeof contractId !== 'string' || !contractId) return reject('missing contractId');
    const verifier = contractVerifiers[contractId];
    if (!verifier) return reject(`unregistered contract: ${contractId}`);
    if (![claimId, from, to, nonce, signerPubkey, signature].every((v) => typeof v === 'string' && v)) return reject('malformed contract-payout transfer fields');
    if (state.usedNonces[nonce]) return reject('nonce already used');
    if (!(await verifyTransferAuthorization({ claimId, from, to, nonce, timestamp, signerPubkey, signature }))) return reject('invalid transfer signature');
    const verified = await verifier(payload);
    if (!verified) return reject(`contract '${contractId}' rejected its own real conditions`);
    if (verified.claimId !== claimId || verified.from !== from || verified.to !== to || verified.nonce !== nonce || verified.signature !== signature) {
      return reject('contract verifier returned fields not matching the real, submitted event');
    }
    try {
      const { state: conservation } = transfer(state.conservation, { claimId, from, to, n: 0, derivation: 'identity' }, derivations);
      return { ...state, conservation, usedNonces: { ...state.usedNonces, [nonce]: true } };
    } catch (e) {
      return reject(e.message);
    }
  }

  return state;
}

export async function materializeWallet(rewardParams, orderedEvents, onProgress, verifyFn, contractVerifiers = {}) {
  let state = initialWalletState();
  for (let i = 0; i < orderedEvents.length; i++) {
    state = await applyWalletEvent(rewardParams, state, orderedEvents[i], verifyFn, contractVerifiers);
    if (onProgress && i % 20 === 0) onProgress(i + 1, orderedEvents.length);
  }
  if (onProgress) onProgress(orderedEvents.length, orderedEvents.length);
  return state;
}

export function spendableClaims(state, domain) {
  return Object.values(state.conservation.claims).filter((c) => c.owner === domain && c.status === 'active');
}

export function totalBalance(rewardParams, state, domain) {
  const unclaimed = claimableNow(rewardParams, state.accrual, domain);
  const claimed = spendableClaims(state, domain).reduce((sum, c) => sum + c.amount, 0n);
  return unclaimed + claimed;
}
