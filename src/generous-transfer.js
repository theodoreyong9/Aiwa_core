// A real, deterministic mechanism — never randomness, exactly like
// mining: the outcome is entirely a pure function of real, public
// inputs, computable by anyone, verifiable by anyone. What makes it
// unpredictable in advance is only that one of those inputs is a
// real, sequential VDF output that genuinely does not exist yet —
// the identical property that makes a Bitcoin block's hash
// unpredictable before it's mined, never a random-number generator
// anywhere.
//
// The mechanism: a real donor optionally, voluntarily commits — at
// the moment of an ordinary, real transfer — to an additional, real
// bonus, payable only if a specific, real, future progression event
// of the RECIPIENT's own chain (never the donor's, never chosen by
// either party) produces a hash meeting a real, public threshold.
//
// Real security properties, each verified concretely below:
//  - No grinding: progression is strictly sequential (progression.js),
//    so at most one real epoch can ever include the donor's own
//    commitment as an additional parent — never a range of future
//    epochs to search through.
//  - No prediction: neither party can know a real VDF output before
//    it is genuinely, sequentially computed.
//  - No fabricated value: a real bonus is real, already-owned AIWA
//    the donor explicitly, irrevocably signed away in advance —
//    never created from nothing, never touching any other domain's
//    funds.
//  - Enforceable by anyone: the recipient (or any third party) can
//    construct and submit the real proof themselves, from already-
//    public data — the donor's own cooperation is never required
//    after the fact.

import { ed25519 } from '@noble/curves/ed25519.js';
import { verifyVdfChain, vdfSeed } from './vdf.js';

// A real, public, versioned identifier for this specific contract —
// never mangled into an address (a domain's own address is a direct
// cryptographic proof, SHA-256 of a real public key; prefixing or
// suffixing it risks real confusion about which real destination a
// transfer actually targets). Instead, every real event this contract
// produces carries this id as an explicit, separate field — anyone
// scanning the log recognizes "this belongs to this contract"
// unambiguously, and any later, composing contract references this
// same id explicitly (e.g. its own events carrying a real
// `wrapsContractId: CONTRACT_ID` field) rather than encoding anything
// into an address. "Upstream" (other contracts building on this one)
// and "downstream" (users sending through it directly) both resolve
// to the identical, real, public string — never two different
// addressing schemes to keep in sync.
export const CONTRACT_ID = 'aiwa-generous-transfer-v1';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(new Uint8Array(digest));
}

function canonicalCommitmentMessage({ contractId, baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits }) {
  return JSON.stringify({ contractId, baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits });
}

/**
 * A real, signed statement by the donor: "if a real, future
 * progression event of `to`'s own chain, chained from this exact
 * commitment, produces a hash meeting `thresholdBits`, I authorize
 * moving `bonusAmount` from my own, already-owned `bonusClaimId` to
 * `to`." Irrevocable once signed — the donor cannot later refuse.
 * Always carries the real, public `CONTRACT_ID` as part of what's
 * actually signed — never decorative, since it's verified below like
 * every other field.
 */
export async function buildGenerousSendCommitment(keypair, { baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits }) {
  if (!Number.isInteger(thresholdBits) || thresholdBits < 0 || thresholdBits > 256) {
    throw new RangeError(`thresholdBits must be a real integer in [0, 256], got ${thresholdBits}`);
  }
  const fields = { contractId: CONTRACT_ID, baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits };
  const message = new TextEncoder().encode(canonicalCommitmentMessage(fields));
  const signature = ed25519.sign(message, keypair.secretKey.slice(0, 32));
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(keypair.publicKey.toBytes()) };
}

export function verifyGenerousSendSignature(commitment) {
  try {
    const { contractId, baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits, signature, signerPubkey } = commitment;
    if (contractId !== CONTRACT_ID) return false; // a real, explicit mismatch — never assumed to be this contract by default
    const message = new TextEncoder().encode(canonicalCommitmentMessage({ contractId, baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits }));
    return ed25519.verify(hexToBytes(signature), message, hexToBytes(signerPubkey));
  } catch {
    return false;
  }
}

/**
 * The real, deterministic, pure hash — never a random draw. Uses the
 * real, raw VDF output string itself, never the qualifying event's
 * own full id: an earlier version used the full id, and a real,
 * concrete attack was found and closed here before ever being
 * shipped — the full id includes cheaply-variable fields (which
 * extra parents are attached), letting a recipient cheaply preview
 * many candidate outcomes by reusing the SAME real, already-computed
 * VDF output with different placeholder parents, without ever
 * redoing the real, expensive sequential work. The raw VDF output
 * itself cannot be varied this way — producing a different one
 * requires genuinely, sequentially recomputing a real, later epoch,
 * which progression's own strict sequentiality already prevents from
 * happening more than once for the real "next" epoch.
 */
export async function computeOutcomeHash(generousSendEventId, qualifyingEpochVdfOutput) {
  return sha256Hex(`${generousSendEventId}:${qualifyingEpochVdfOutput}`);
}

function countLeadingZeroBits(hexString) {
  let bits = 0;
  for (const ch of hexString) {
    const nibble = parseInt(ch, 16);
    if (nibble === 0) { bits += 4; continue; }
    // real, partial nibble — count the real leading zero bits within it
    bits += Math.clz32(nibble) - 28;
    break;
  }
  return bits;
}

/**
 * @returns {boolean} true only if the real, deterministic hash meets
 * the real, public threshold this exact commitment specified.
 */
export function checkOutcome(hashHex, thresholdBits) {
  return countLeadingZeroBits(hashHex) >= thresholdBits;
}

/**
 * The one, real, unambiguous check closing the "try many future
 * epochs" attack: a real progression event only legitimately
 * qualifies if the generous-send event id is genuinely among its
 * real parents — and progression's own strict sequentiality means a
 * domain has at most one real "next" epoch at any point, never a
 * range to search across.
 *
 * Also requires, and independently re-verifies, the real VDF proof
 * itself (never trusted from the event's own shape alone) — an
 * earlier version skipped this, which would have let a fabricated
 * `vdfOutput` (never really, sequentially computed at all) be
 * ground for a favorable outcome, closed here before ever being
 * shipped. `priorVdfOutput` is the domain's own real, already-
 * verified previous epoch's output — the caller's own responsibility
 * to supply from an already-trusted progression chain, never
 * re-derived here from anything unverified.
 */
export async function verifyQualifyingEpoch(epochEvent, generousSendEventId, expectedRecipientDomain, priorVdfOutput) {
  if (!epochEvent || epochEvent.payload?.type !== 'progression') return false;
  if (epochEvent.payload.domain !== expectedRecipientDomain) return false;
  if (!Array.isArray(epochEvent.parents) || !epochEvent.parents.includes(generousSendEventId)) return false;
  const { vdfIterations, vdfOutput } = epochEvent.payload;
  if (!Number.isInteger(vdfIterations) || vdfIterations < 1) return false;
  const seed = vdfSeed(expectedRecipientDomain, priorVdfOutput ?? 'genesis');
  return verifyVdfChain(seed, vdfIterations, vdfOutput);
}

/**
 * The full, real, combined resolution — every real check composed;
 * a real, honest null on any single failure, never a partial or
 * assumed result.
 *
 * @returns {{ won: boolean, bonusClaimId: string, bonusAmount: string, to: string } | null}
 */
export async function resolveGenerousSend({ commitment, generousSendEventId, qualifyingEpochEvent, priorVdfOutput }) {
  if (!verifyGenerousSendSignature(commitment)) return null;
  if (!(await verifyQualifyingEpoch(qualifyingEpochEvent, generousSendEventId, commitment.to, priorVdfOutput))) return null;
  const hash = await computeOutcomeHash(generousSendEventId, qualifyingEpochEvent.payload.vdfOutput);
  const won = checkOutcome(hash, commitment.thresholdBits);
  return { won, bonusClaimId: commitment.bonusClaimId, bonusAmount: commitment.bonusAmount, to: commitment.to };
}

/**
 * The one, real, standard-shaped entry point wallet.js's own generic
 * `contract-payout` dispatch (registered by contractId — never
 * hardcoded per contract) calls into. Every real, contract-specific
 * check this file owns — commitment signature, qualifying epoch,
 * real VDF re-verification, the real outcome threshold, and that the
 * pre-signed transfer's own fields genuinely match what the
 * commitment actually authorized — is composed here, once. Returns a
 * real, ready-to-apply transfer shape identical to an ordinary
 * `transfer` event's own fields, or a real, honest null on any
 * single failure — wallet.js never re-implements any of this itself.
 *
 * @returns {{ claimId: string, from: string, to: string, nonce: string, timestamp: number, signerPubkey: string, signature: string } | null}
 */
export async function verifyPayout(payload) {
  const { claimId, from, to, nonce, timestamp, signerPubkey, signature, commitment, generousSendEventId, qualifyingEpochEvent, priorVdfOutput } = payload;
  if (![claimId, from, to, nonce, signerPubkey, signature].every((v) => typeof v === 'string' && v)) return null;
  if (!commitment || !generousSendEventId || !qualifyingEpochEvent) return null;
  if (commitment.bonusClaimId !== claimId || commitment.to !== to) return null;
  const result = await resolveGenerousSend({ commitment, generousSendEventId, qualifyingEpochEvent, priorVdfOutput });
  if (!result || !result.won) return null;
  return { claimId, from, to, nonce, timestamp, signerPubkey, signature };
}

/**
 * Builds the one, real, publishable event a donor creates to start a
 * real generous send — the commitment (§ above) and a real,
 * pre-signed bonus transfer, bundled together. `buildTransfer` is the
 * real, already-existing `buildSignedTransferEvent` from `wallet.js`
 * — reused directly, never duplicated, so this always signs the
 * identical real message format `wallet.js`'s own transfer
 * verification already expects. `donorDomain` must be the real,
 * already-derived domain id for `keypair` — never re-derived here, to
 * keep this file independent of the identity module.
 *
 * @returns {object} a real, ready-to-publish `generous-send-offer` payload
 */
export async function buildOfferPayload(keypair, donorDomain, { baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits }, buildTransfer) {
  const commitment = await buildGenerousSendCommitment(keypair, { baseTransferId, to, bonusClaimId, bonusAmount, thresholdBits });
  const preSignedTransfer = await buildTransfer({ claimId: bonusClaimId, from: donorDomain, to }, keypair.secretKey.slice(0, 32), keypair.publicKey.toBytes());
  return { type: 'generous-send-offer', commitment, preSignedTransfer };
}
