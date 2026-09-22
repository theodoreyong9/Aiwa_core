// A real, second, composing contract — proof that composability is a
// real, working mechanism, not only a documented intention. A real
// third party pre-commits to also sending a bonus IF a specific,
// real, already-existing generous-transfer.js offer resolves as a
// win — verified by directly calling that contract's own real,
// exported verification logic, never a re-implementation of it.
//
// The real mechanism, precisely: no shared execution environment
// exists here (no EVM) — "composing" can only ever mean a real,
// ordinary JS import, calling another contract's own real, exported
// function. This file does exactly that, and nothing else.

import { ed25519 } from '@noble/curves/ed25519.js';
import { resolveGenerousSend, CONTRACT_ID as WRAPPED_CONTRACT_ID } from './generous-transfer.js';

export const CONTRACT_ID = 'aiwa-matching-v1';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function canonicalMatchMessage({ contractId, wrapsContractId, wrappedGenerousSendEventId, matchClaimId, matchAmount, to }) {
  return JSON.stringify({ contractId, wrapsContractId, wrappedGenerousSendEventId, matchClaimId, matchAmount, to });
}

/**
 * A real, signed statement by a third-party matcher: "if the real,
 * already-existing generous-transfer offer identified by
 * `wrappedGenerousSendEventId` resolves as a real win, I additionally
 * authorize moving `matchAmount` from my own real `matchClaimId` to
 * `to`." `wrapsContractId` is real, signed, human-checkable
 * transparency about which real contract this composes with — the
 * actual security comes from the hardcoded, real import above, never
 * from this field alone (a field could be spoofed; a real, direct
 * function call cannot).
 */
export async function buildMatchCommitment(keypair, { wrappedGenerousSendEventId, matchClaimId, matchAmount, to }) {
  const fields = { contractId: CONTRACT_ID, wrapsContractId: WRAPPED_CONTRACT_ID, wrappedGenerousSendEventId, matchClaimId, matchAmount, to };
  const message = new TextEncoder().encode(canonicalMatchMessage(fields));
  const signature = ed25519.sign(message, keypair.secretKey.slice(0, 32));
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(keypair.publicKey.toBytes()) };
}

export function verifyMatchCommitmentSignature(commitment) {
  try {
    const { contractId, wrapsContractId, wrappedGenerousSendEventId, matchClaimId, matchAmount, to, signature, signerPubkey } = commitment;
    if (contractId !== CONTRACT_ID) return false;
    if (wrapsContractId !== WRAPPED_CONTRACT_ID) return false; // a real, explicit mismatch — never assumed to wrap the right contract by default
    const message = new TextEncoder().encode(canonicalMatchMessage({ contractId, wrapsContractId, wrappedGenerousSendEventId, matchClaimId, matchAmount, to }));
    return ed25519.verify(hexToBytes(signature), message, hexToBytes(signerPubkey));
  } catch {
    return false;
  }
}

/**
 * The real, generic wallet.js entry point, for this contract.
 * `wrappedProof` carries everything needed to independently
 * re-verify the real, wrapped generous-transfer outcome — this
 * contract never trusts a bare "it won" claim, always recomputes it
 * itself, by real, direct composition.
 */
export async function verifyPayout(payload) {
  const { claimId, from, to, nonce, timestamp, signerPubkey, signature, matchCommitment, wrappedProof } = payload;
  if (![claimId, from, to, nonce, signerPubkey, signature].every((v) => typeof v === 'string' && v)) return null;
  if (!matchCommitment || !wrappedProof) return null;
  if (!verifyMatchCommitmentSignature(matchCommitment)) return null;
  if (matchCommitment.matchClaimId !== claimId || matchCommitment.to !== to) return null;
  if (matchCommitment.wrappedGenerousSendEventId !== wrappedProof.generousSendEventId) return null;

  // The real, direct composition: this contract's own outcome
  // depends on genuinely, independently re-resolving the wrapped
  // contract's own real condition — never a re-implementation, the
  // identical, real function `generous-transfer.js` itself exports.
  const wrappedResult = await resolveGenerousSend(wrappedProof);
  if (!wrappedResult || !wrappedResult.won) return null;

  return { claimId, from, to, nonce, timestamp, signerPubkey, signature };
}
