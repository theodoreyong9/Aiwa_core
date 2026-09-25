// A real, self-signed checkpoint: a domain's own real, materialized
// wallet state, as of a specific real set of log heads, embedded
// directly in a real, signed event — "this is genuinely my own state
// as of here" — never a separate, unsigned side-channel.
//
// Built with createEvent, so the outer envelope's own real signature
// already covers everything — no separate embedded signerPubkey/
// signature needed here, unlike accrual.js's own buildSignedClaimEvent/
// buildSignedAccrualEvent. Those exist specifically because a reducer
// only ever sees payload with `author` already stripped by
// adapt-event.js's own toReducerEvent; a checkpoint is instead read
// directly off the real wire event, before that stripping happens, so
// the real, already-verified `event.author` (EventLog.append() already
// guarantees it really derives from event.authorPublicKey before any
// event is ever stored) is available and sufficient on its own.
//
// The one check every real consumer of a checkpoint must make:
// event.author === event.payload.domain — otherwise anyone could
// inject a checkpoint claiming an arbitrary, fabricated state for a
// domain that never signed it. The identical class of gap accrual.js's
// own 'claim'/'accrual' signer-scoping fix closed, applied here from
// the start rather than discovered after the fact.
//
// HONEST LIMIT, stated plainly: a checkpoint only ever lets a domain
// vouch for ITS OWN real past. A peer who already independently
// verified everything up to a checkpoint loses nothing by trusting it
// afterward (it is genuinely their own already-verified work,
// summarized). A brand-new peer who receives ONLY a checkpoint (its
// prior history already pruned — see EventLog.pruneBeforeCheckpoint)
// can no longer independently re-derive that summarized state from
// genesis; they trade full independent verifiability for a real,
// signed assertion by the domain's own key about its own past. That
// tradeoff is inherent to any checkpoint/pruning scheme (the identical
// one Ethereum's own weak-subjectivity checkpoints make) — not a flaw
// specific to this implementation, and not hidden here: a peer that
// needs full independent verification should fetch the pre-pruned
// history from a peer that still holds it, or simply not prune.

import { createEvent } from './event.js';

const BIGINT_TAG = '__bigint__:';

function replacer(_key, value) {
  return typeof value === 'bigint' ? `${BIGINT_TAG}${value.toString()}` : value;
}
function reviver(_key, value) {
  return typeof value === 'string' && value.startsWith(BIGINT_TAG) ? BigInt(value.slice(BIGINT_TAG.length)) : value;
}

/** BigInt values (claim amounts, accrual balances) have no native JSON representation — tagged here, revived back to real bigint on load, never silently coerced to a lossy float or an unrecoverable string. */
export function serializeWalletState(state) {
  return JSON.stringify(state, replacer);
}
export function deserializeWalletState(serialized) {
  return JSON.parse(serialized, reviver);
}

/** A real, self-signed checkpoint event for `identity`'s own domain, summarizing `walletState` as of `coveredHeads` (the log's own real heads at the moment `walletState` was computed). */
export async function buildCheckpointEvent(identity, { logDomain, parents, coveredHeads, walletState }) {
  return createEvent(identity, {
    domain: logDomain,
    parents,
    type: 'checkpoint',
    payload: { domain: identity.id, coveredHeads, walletState: serializeWalletState(walletState) },
  });
}

/** Only a checkpoint whose real, already-verified signer IS the domain it claims to summarize is ever trustworthy as a materialization base or a pruning basis. */
export function verifyCheckpoint(event) {
  return !!event && event.type === 'checkpoint' && !!event.payload && event.author === event.payload.domain;
}

/** The real, materialized wallet state a valid checkpoint embeds, or null if `event` is not a real, self-authored checkpoint. */
export function checkpointWalletState(event) {
  if (!verifyCheckpoint(event)) return null;
  return deserializeWalletState(event.payload.walletState);
}

/** The most recent real, self-authored checkpoint for `domain` in `log`, or null if none exists yet. A linear scan — checkpoints are rare, deliberate, occasional events, never a per-transaction cost, so this is never the hot path materializeWallet's own per-call cost lives on. */
export async function findLatestCheckpoint(log, domain) {
  const ids = await log.backend.allIds();
  let latest = null;
  for (const id of ids) {
    const event = await log.get(id);
    if (event && event.type === 'checkpoint' && event.author === domain && verifyCheckpoint(event)) {
      if (!latest || event.createdAt > latest.createdAt) latest = event;
    }
  }
  return latest;
}
