// A domain's own progression epoch advances only through a valid
// transition: monotonic (+1 exactly), causally chained to the domain's
// last accepted transition, carrying a real sequential VDF proof (see
// vdf.js) — bounding the RATE of advancement, not calendar time — AND,
// like every other event type that changes a domain's own economic
// state, a real Ed25519 signature proving the real signer controls
// `domain`.
//
// THE REAL GAP THIS CLOSES, found the same way accrual.js's own
// 'claim'/'accrual' gap was: the VDF proof alone is NOT a real proof
// of who submitted it — vdfSeed(domain, previousOutput) is a public,
// deterministic function of values already visible to anyone watching
// the log, so anyone (not just the domain owner) can compute the exact
// same next-epoch vdfOutput and publish it as a 'progression' event
// naming that domain. Not a theft — the resulting epoch is exactly
// what the real owner's own hardware would have produced — but it lets
// anyone advance a domain's own qTotal (domainAge, reward.js's own
// denominator reference) without consent, at zero cost to themselves
// beyond the real, sequential VDF work. Verified directly against
// reward.js's own real formula: reward(b=100, q=1, qTotal, T=0) drops
// from ~0.087 at qTotal=1 to ~0.0097 at qTotal=20000 — a real,
// permanent, roughly 9x griefing reduction in a domain's own future
// reward per accrual, since domainAge never resets. Signer-scoped from
// here on, mirroring accrual.js's own buildSignedAccrualEvent/
// verifyAccrualAuthorization exactly (adapt-event.js's own
// toReducerEvent strips the outer event envelope's real `author`
// before any reducer ever sees it, by design — see its own header —
// so this embeds its own inner signature the identical way).
//
// Events here use this package's own internal convention: {id,
// parents, payload}, with payload.type — see adapt-event.js for the
// bridge from event.js's own wire event shape.

import { vdfSeed, verifyVdfChain } from './vdf.js';
import { deriveId } from './identity.js';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function canonicalProgressionMessage({ domain, epoch, vdfIterations, vdfOutput, nonce, timestamp }) {
  return JSON.stringify({ domain, epoch, vdfIterations, vdfOutput, nonce, timestamp });
}

/** A real, domain-owner-signed progression transition — the only way a 'progression' event now passes applyProgressionEvent's own authorization check. */
export async function buildSignedProgressionEvent(fields, signerSeed, signerPubkeyBytes, { now = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const withMeta = { ...fields, nonce, timestamp: now };
  const signature = ed25519.sign(new TextEncoder().encode(canonicalProgressionMessage(withMeta)), signerSeed);
  return { ...withMeta, signerPubkey: toHex(signerPubkeyBytes), signature: toHex(signature) };
}

async function verifyProgressionAuthorization(payload) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { domain, epoch, vdfIterations, vdfOutput, nonce, timestamp, signerPubkey, signature } = payload;
  if (typeof signerPubkey !== 'string' || typeof signature !== 'string') return false;
  if ((await deriveId(fromHex(signerPubkey))) !== domain) return false; // only the domain's real key can advance its own progression
  try {
    return ed25519.verify(fromHex(signature), new TextEncoder().encode(canonicalProgressionMessage({ domain, epoch, vdfIterations, vdfOutput, nonce, timestamp })), fromHex(signerPubkey));
  } catch {
    return false;
  }
}

export function initialProgressionState() {
  return { domains: {}, rejections: [] };
}

/**
 * The real parent set a NEW progression event for a domain must declare.
 *
 * applyProgressionEvent's own causal-chain check below requires the
 * domain's last accepted progression event id to be a DIRECT parent —
 * not just a transitive ancestor. `heads` (a log's own current heads,
 * the parents every other real event builder in this codebase uses)
 * only satisfies that for free when nothing else was published for
 * this domain since the last progression tick. The moment any other
 * event (an accrual, a claim, a checkpoint...) becomes the sole head in
 * between — a completely ordinary sequence, e.g. recordCommitment()
 * right before advanceProgress() — `heads` alone silently drops the
 * chain, and every progression event from then on is permanently
 * rejected as "not chained", since the reducer's own lastId can then
 * never again match a real parent.
 *
 * Real fix, not a verification workaround: a progression event
 * genuinely does have two real causal dependencies — the log's current
 * tip, AND its own type's last accepted transition — so it should
 * honestly declare both as parents (a real merge, not a forced choice).
 * Any real progression-event builder should route its parents through
 * this, rather than reimplementing the same rule.
 */
export function progressionParents(heads, lastId) {
  return lastId && !heads.includes(lastId) ? [...heads, lastId] : heads;
}

// verifyFn defaults to the real, main-thread verifyVdfChain — every
// existing call site, and this project's own Node-based test suite,
// keeps working unchanged. A caller with access to a real worker
// thread (catching up on a real, possibly large backlog) can inject a
// worker-backed verifier instead, so that even this one-time catch-up
// work never has to run on the same thread that also needs to render
// and handle input.
export async function applyProgressionEvent(state, event, verifyFn = verifyVdfChain) {
  verifyFn ??= verifyVdfChain;
  const payload = event.payload;
  if (!payload || payload.type !== 'progression') return state;

  const { domain, epoch, vdfIterations, vdfOutput } = payload;
  const reject = (reason) => ({
    ...state,
    rejections: [...state.rejections, { eventId: event.id, domain, reason }],
  });

  if (typeof domain !== 'string' || domain.length === 0) return reject('missing domain');
  if (!Number.isInteger(epoch) || epoch < 1) return reject('epoch must be a positive integer');

  const current = state.domains[domain] ?? { epoch: 0, lastId: null, vdfOutput: null };

  if (epoch !== current.epoch + 1) return reject(`expected epoch ${current.epoch + 1}, got ${epoch}`);
  if (current.lastId !== null && !event.parents.includes(current.lastId)) {
    return reject(`does not chain from this domain's last accepted transition ${current.lastId}`);
  }
  if (!Number.isInteger(vdfIterations) || vdfIterations < 1) return reject('vdfIterations must be a positive integer');
  if (typeof payload.nonce !== 'string' || !payload.nonce || typeof payload.signerPubkey !== 'string' || typeof payload.signature !== 'string') {
    return reject('malformed progression payload — missing real signature fields');
  }
  if (!(await verifyProgressionAuthorization(payload))) {
    return reject('invalid signature: only the domain itself can advance its own progression');
  }

  const seed = vdfSeed(domain, current.vdfOutput ?? 'genesis');
  if (!(await verifyFn(seed, vdfIterations, vdfOutput))) {
    return reject('VDF proof does not verify against the recomputed chain');
  }

  return { ...state, domains: { ...state.domains, [domain]: { epoch, lastId: event.id, vdfOutput } } };
}

export async function materializeProgression(orderedEvents, verifyFn = verifyVdfChain) {
  verifyFn ??= verifyVdfChain;
  let state = initialProgressionState();
  for (const event of orderedEvents) state = await applyProgressionEvent(state, event, verifyFn);
  return state;
}
