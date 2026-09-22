// The real, shared identity primitive — the identical, real pattern
// reused, unchanged in principle, across AIWA_chain's own domain-id,
// AIWA CV's own identity.js, and the architecture doc's own real
// Identity interface: an identity is a real, cryptographic root, not
// merely a user account. It signs events, authorizes capabilities,
// and authenticates peers — the same real root for a human, an
// application, a service, or an agent.

import { ed25519 } from '@noble/curves/ed25519.js';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The real, deterministic id — SHA-256 of the real public key, identical in spirit across every real project this unifies. */
export async function deriveId(publicKeyBytes) {
  const digest = await crypto.subtle.digest('SHA-256', publicKeyBytes);
  return toHex(new Uint8Array(digest));
}

export async function generateIdentity() {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  const id = await deriveId(publicKey);
  return new Identity({ id, secretKeyHex: toHex(secretKey), publicKeyHex: toHex(publicKey) });
}

export function identityFromSecretKey(secretKeyHex) {
  const publicKey = ed25519.getPublicKey(hexToBytes(secretKeyHex));
  const publicKeyHex = toHex(publicKey);
  return deriveId(publicKey).then((id) => new Identity({ id, secretKeyHex, publicKeyHex }));
}

/** A real, public-only identity — can verify, can never sign. Used to represent a real, remote peer. */
export function publicIdentity(publicKeyHex) {
  return deriveId(hexToBytes(publicKeyHex)).then((id) => new Identity({ id, secretKeyHex: null, publicKeyHex }));
}

export class Identity {
  constructor({ id, secretKeyHex, publicKeyHex }) {
    this.id = id;
    this.publicKey = publicKeyHex;
    this._secretKey = secretKeyHex;
  }

  /** Real, exact bytes in — real, exact signature out. Never signs on behalf of a real, public-only identity. */
  async sign(bytes) {
    if (!this._secretKey) throw new Error('This real identity has no real secret key — it can verify, never sign.');
    return toHex(ed25519.sign(bytes, hexToBytes(this._secretKey)));
  }

  async verify(bytes, signatureHex) {
    try {
      return ed25519.verify(hexToBytes(signatureHex), bytes, hexToBytes(this.publicKey));
    } catch {
      return false;
    }
  }
}
