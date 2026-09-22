// A real, general mechanism — not specific to any one contract — for
// publishing a contract's own real identity as an ordinary event in
// the same log everything else already lives in. No new
// infrastructure: @aiwa/record's own content-addressing (its own
// computeEventId) is the entire mechanism. Once published and
// received by other domains (via replication, like any other real
// event), a contract's own id is immutable in the identical, real
// sense every other event already is — not because of any new
// guarantee, but because this is simply what appending an event has
// always meant here.
//
// This deliberately does not create a single, network-enforced
// "canonical registry." Multiple, real, competing contracts can
// coexist under different names, each with its own real, verifiable
// identity — wallets and users choose which to trust, exactly like
// there is no single "true" token contract on any existing chain.

import { createEvent } from '@aiwa/record';

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The real, content-derived hash of a contract's own real source. */
export async function computeContractHash(sourceCode) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sourceCode));
  return toHex(new Uint8Array(digest));
}

/**
 * Publishes a real `contract-spec` event to `log` (an @aiwa/record
 * EventLog) — the event's own real, content-addressed id becomes the
 * contract's real, immutable identity from this point on. `identity`
 * must be a real, secret-key-bearing @aiwa/record Identity: an event
 * here is signed exactly like any other. `sourceCode` is embedded in
 * full — never only its hash — so the real code is genuinely
 * recoverable by anyone who receives this event, not merely
 * fingerprint-verifiable against a copy kept elsewhere. `sourceHash`
 * is included alongside for quick, cheap comparison without
 * re-hashing the full body every time.
 *
 * @returns {{ specEventId: string, sourceHash: string }}
 */
export async function publishContractSpec(identity, log, domain, { name, version, sourceCode, description }) {
  const sourceHash = await computeContractHash(sourceCode);
  const event = await createEvent(identity, {
    domain,
    parents: await log.head(),
    type: 'contract-spec',
    payload: { name, version, sourceCode, sourceHash, description },
  });
  await log.append(event);
  return { specEventId: event.id, sourceHash };
}

/**
 * The real, actual source code, recovered directly from an
 * already-received real event — never assumed to live anywhere else.
 * Takes this package's own reducer-shaped event ({payload: {type,
 * ...}}) — see adapt-event.js.
 */
export function readContractSource(specEvent) {
  if (!specEvent || specEvent.payload?.type !== 'contract-spec') return null;
  return specEvent.payload.sourceCode ?? null;
}

/**
 * @returns {boolean} true only if `sourceCode`'s own real hash
 * genuinely matches what a real, already-published contract-spec
 * event claims — never trusted from a name or version number alone.
 */
export async function verifyContractSource(specEvent, sourceCode) {
  if (!specEvent || specEvent.payload?.type !== 'contract-spec') return false;
  const realHash = await computeContractHash(sourceCode);
  return realHash === specEvent.payload.sourceHash;
}

/** Every real contract-spec event found in `events` — pure, no browser dependency. Reducer-shaped events. */
export function scanContractSpecs(events) {
  return events.filter((ev) => ev.payload?.type === 'contract-spec').map((ev) => ({ id: ev.id, ...ev.payload }));
}

/**
 * The one, real, structural close to the contractId-collision risk —
 * verified concretely: a real signature alone only ever proves
 * "signed by this key, over this exact content," never "this is
 * really the trusted module you think it is." Nothing stops a real,
 * different, possibly malicious contract from simply choosing an
 * existing `contractId` string.
 *
 * This makes registration itself demand proof, not just a name:
 * `verifierFn` is only ever added to the real registry if `sourceCode`
 * genuinely, currently hashes to `expectedHash` — a real, deliberate
 * pin the application's own code carries, never trusted from whatever
 * a contract happens to claim about itself. A real mismatch throws
 * outright — never a silent skip, never a partial registration.
 *
 * @returns {object} a real, new registry with the real entry added
 */
export async function registerVerifiedContract(contractVerifiers, { contractId, sourceCode, expectedHash, verifyPayoutFn }) {
  const realHash = await computeContractHash(sourceCode);
  if (realHash !== expectedHash) {
    throw new Error(`Refusing to register '${contractId}': real source hash ${realHash} does not match the expected, pinned ${expectedHash} — this is not genuinely the trusted contract it claims to be.`);
  }
  return { ...contractVerifiers, [contractId]: verifyPayoutFn };
}
