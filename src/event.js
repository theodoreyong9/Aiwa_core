// The real, canonical event — `parents`, never a bare timestamp,
// because parents encode real causal dependency ("B depends on A"),
// while a timestamp only ever encodes real arrival order ("B arrived
// after A").

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalize(value[key]);
    return sorted;
  }
  return value;
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function deriveIdFromPublicKey(publicKeyHex) {
  const digest = await crypto.subtle.digest('SHA-256', hexToBytes(publicKeyHex));
  return toHex(new Uint8Array(digest));
}

async function verifySignatureWithPublicKey(publicKeyHex, bytes, signatureHex) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  try {
    return ed25519.verify(hexToBytes(signatureHex), bytes, hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

/** The real, exact bytes an event's own real id and real signature are both computed over — parents sorted, payload canonicalized. */
function coreBytes({ domain, author, authorPublicKey, parents, type, payload, createdAt }) {
  const core = { domain, author, authorPublicKey, parents: [...parents].sort(), type, payload: canonicalize(payload), createdAt };
  return new TextEncoder().encode(JSON.stringify(core));
}

export async function computeEventId(coreBytesValue) {
  const digest = await crypto.subtle.digest('SHA-256', coreBytesValue);
  return toHex(new Uint8Array(digest));
}

/**
 * Real, pure construction: builds a real, canonical, content-addressed,
 * signed event. `identity` must be a real, secret-key-bearing
 * Identity. The real, public key is carried directly in the event —
 * `author` alone (a one-way hash) can never be reversed back into a
 * real key for verification, so any real verifier needs it present
 * and checked, never looked up from an untrusted, separate registry.
 */
export async function createEvent(identity, { domain, parents = [], type, payload, createdAt = Date.now() }) {
  const author = identity.id;
  const authorPublicKey = identity.publicKey;
  const core = { domain, author, authorPublicKey, parents, type, payload, createdAt };
  const bytes = coreBytes(core);
  const id = await computeEventId(bytes);
  const signature = await identity.sign(bytes);
  return { id, domain, author, authorPublicKey, parents, type, payload, createdAt, signature };
}

/**
 * Real, pure, and genuinely self-contained verification — no external
 * identity resolution required. Three real, independent checks, all
 * of which must pass: (1) the real, embedded public key genuinely
 * derives the claimed real `author` id — closing the real gap where
 * someone could claim any id while signing with an unrelated real
 * key; (2) the real, recomputed content-addressed id matches; (3) the
 * real signature verifies against the real, embedded public key.
 */
export async function verifyEvent(event) {
  const derivedId = await deriveIdFromPublicKey(event.authorPublicKey);
  if (derivedId !== event.author) return { valid: false, reason: 'real, embedded public key does not derive the claimed real author id' };

  const bytes = coreBytes(event);
  const realId = await computeEventId(bytes);
  if (realId !== event.id) return { valid: false, reason: 'real, recomputed id does not match the claimed id — content was tampered with' };

  const sigValid = await verifySignatureWithPublicKey(event.authorPublicKey, bytes, event.signature);
  if (!sigValid) return { valid: false, reason: 'real signature does not verify' };
  return { valid: true };
}
