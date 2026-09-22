// A mandatory, signed, per-epoch commitment to what a domain has (or
// has not) received from other domains. Two real properties:
//
// - recurring cost: a signed commitment at every progression epoch,
//   empty or full, turns identity maintenance into an ongoing cost,
//   not a one-time registration burn.
// - reception monotonicity: a domain's own successive claims about
//   what it has seen of another domain must never go backwards.
//
// Explicitly does not prove two domains are distinct real entities
// (identity-cost.js's job) or rule out a genuinely collaborating pair
// fabricating a consistent history together — no purely relational
// mechanism, with no external anchor, can.

export function initialMirrorState() {
  return { commitments: {}, maxSeenEpoch: {}, rejections: [] };
}

export function canonicalReceptionMessage({ domain, epoch, kind, receivedFrom }) {
  const sorted = [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId));
  return JSON.stringify({ domain, epoch, kind, receivedFrom: sorted });
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// A real, signed reception commitment — this domain really attesting
// to what it has really observed of `sourceDomain`'s own progression,
// after really importing it. `epoch` is this domain's own current
// commitment sequence number, never the observed domain's. The
// caller wraps the returned payload into a 'reception' event
// (type + this payload) and appends it — this module never touches an
// EventLog directly.
export async function buildReceptionCommitment(keypair, domain, epoch, sourceDomain, sourceEventIds) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const receivedFrom = sourceEventIds.map((eventId) => ({ sourceDomain, eventId }));
  const fields = { domain, epoch, kind: 'full', receivedFrom };
  const message = new TextEncoder().encode(canonicalReceptionMessage(fields));
  const signature = ed25519.sign(message, keypair.secretKey.slice(0, 32));
  return { ...fields, signature: toHex(signature), signerPubkey: toHex(keypair.publicKey.toBytes()) };
}

async function verifyCommitmentSignature(payload) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { deriveId } = await import('./identity.js');
  const fromHex = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  };
  const message = new TextEncoder().encode(canonicalReceptionMessage(payload));
  let valid;
  try {
    valid = ed25519.verify(fromHex(payload.signature), message, fromHex(payload.signerPubkey));
  } catch {
    return false;
  }
  if (!valid) return false;
  return (await deriveId(fromHex(payload.signerPubkey))) === payload.domain;
}

function reject(state, eventId, domain, reason) {
  return { ...state, rejections: [...state.rejections, { eventId, domain, reason }] };
}

export async function applyMirrorEvent(state, event, sourceEpochLookup) {
  const payload = event.payload;
  if (!payload || payload.type !== 'reception') return state;

  const { domain, epoch, kind, receivedFrom, signature, signerPubkey } = payload;
  if (typeof domain !== 'string' || !domain) return reject(state, event.id, domain ?? '', 'missing domain');
  if (!Number.isInteger(epoch) || epoch < 1) return reject(state, event.id, domain, 'epoch must be a positive integer');
  if (kind !== 'empty' && kind !== 'full') return reject(state, event.id, domain, "kind must be 'empty' or 'full'");
  if (!Array.isArray(receivedFrom)) return reject(state, event.id, domain, 'receivedFrom must be an array');
  if (kind === 'empty' && receivedFrom.length !== 0) return reject(state, event.id, domain, "kind='empty' requires an empty receivedFrom");
  if (kind === 'full' && receivedFrom.length === 0) return reject(state, event.id, domain, "kind='full' requires a non-empty receivedFrom");

  if (!(await verifyCommitmentSignature({ domain, epoch, kind, receivedFrom, signature, signerPubkey }))) {
    return reject(state, event.id, domain, 'invalid or non-matching signature');
  }

  const resolvedEpochs = {};
  for (const ref of receivedFrom) {
    if (typeof ref.sourceDomain !== 'string' || typeof ref.eventId !== 'string') {
      return reject(state, event.id, domain, 'malformed receivedFrom entry');
    }
    const sourceEpoch = sourceEpochLookup(ref.sourceDomain, ref.eventId);
    if (sourceEpoch === null || sourceEpoch === undefined) {
      return reject(state, event.id, domain, `claimed reception of '${ref.eventId}' from '${ref.sourceDomain}' does not correspond to a real event there`);
    }
    resolvedEpochs[ref.sourceDomain] = Math.max(resolvedEpochs[ref.sourceDomain] ?? 0, sourceEpoch);
  }

  const priorMax = state.maxSeenEpoch[domain] ?? {};
  for (const [sourceDomain, newMax] of Object.entries(resolvedEpochs)) {
    const previous = priorMax[sourceDomain] ?? 0;
    if (newMax < previous) {
      return reject(state, event.id, domain, `reception monotonicity violated: previously saw '${sourceDomain}' up to epoch ${previous}, now claims only ${newMax}`);
    }
  }

  const newMaxSeenForDomain = { ...priorMax };
  for (const [sourceDomain, newMax] of Object.entries(resolvedEpochs)) {
    newMaxSeenForDomain[sourceDomain] = Math.max(newMaxSeenForDomain[sourceDomain] ?? 0, newMax);
  }

  return {
    ...state,
    commitments: { ...state.commitments, [domain]: [...(state.commitments[domain] ?? []), { domain, epoch, kind, receivedFrom }] },
    maxSeenEpoch: { ...state.maxSeenEpoch, [domain]: newMaxSeenForDomain },
  };
}

// Real, DAG-native derivation of sourceEpochLookup: the epoch that
// produced a given event, found by recomputation, not self-declared.
// Walks real ancestry looking for the domain's highest-epoch
// progression event; a real event with no progression ancestors is a
// legitimate epoch-0 state, never treated as absence. A fabricated or
// misattributed reference is the only real rejection case.
export function deriveSourceEpochLookup(orderedEvents) {
  const byId = new Map(orderedEvents.map((e) => [e.id, e]));
  const SAFETY_BOUND = 10000;

  return (sourceDomain, eventId) => {
    const target = byId.get(eventId);
    if (!target || target.payload?.domain !== sourceDomain) return null;
    if (target.payload?.type === 'progression' && Number.isInteger(target.payload.epoch)) return target.payload.epoch;

    const visited = new Set();
    const queue = [...target.parents];
    let maxEpoch = 0;
    while (queue.length > 0 && visited.size < SAFETY_BOUND) {
      const id = queue.shift();
      if (visited.has(id)) continue;
      visited.add(id);
      const event = byId.get(id);
      if (event) {
        if (event.payload?.type === 'progression' && event.payload?.domain === sourceDomain && Number.isInteger(event.payload.epoch)) {
          maxEpoch = Math.max(maxEpoch, event.payload.epoch);
        }
        queue.push(...event.parents);
      }
    }
    return maxEpoch;
  };
}

export async function materializeMirror(orderedEvents, sourceEpochLookup) {
  let state = initialMirrorState();
  for (const event of orderedEvents) state = await applyMirrorEvent(state, event, sourceEpochLookup);
  return state;
}

// Entropy of a domain's own distribution of reappearances across
// everyone it has committed to observing — a real, computable
// signature, never a proof of real-world independence. A low score is
// a signal, not a verdict: a small, legitimate group that only ever
// interacts within itself produces the same low entropy a colluding
// cluster would.
export function computeResidualDiversity(state, domain) {
  const commits = state.commitments[domain] ?? [];
  const counts = {};
  let total = 0;
  for (const c of commits) {
    for (const ref of c.receivedFrom) {
      counts[ref.sourceDomain] = (counts[ref.sourceDomain] ?? 0) + 1;
      total += 1;
    }
  }
  const distinctSources = Object.keys(counts).length;
  if (total === 0) return { entropy: 0, distinctSources: 0, totalReappearances: 0 };

  let entropy = 0;
  for (const count of Object.values(counts)) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return { entropy, distinctSources, totalReappearances: total };
}
