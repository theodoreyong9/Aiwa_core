// The two states of "last action" mining, readable by anyone who holds a domain's events — an app, a validator, a
// registry — without trusting the domain.
//
//  1. THE MINING STATE of a domain: the capital that mines (the last burn's b), the patience rate T chosen at that
//     burn, the epoch of the last action (burn or claim), the domain's age (its progression epochs), the epochs
//     since the last action, and what is claimable now.
//  2. THE RANKING FIGURE: what an app ranks by — the claimable at this moment and the laps (epochs since the last
//     action), as YourMine's own score and laps are. A figure is read at a moment and frozen by whoever stores it.
//
// In a work-bound deployment (rewardParams.epochIterations) the mining events of a domain are one signed chain: each
// names the one it follows, and the work of an epoch starts from it. `chainHead` is the last one, what the next must
// follow — and what a reader that keeps a baseline asks the domain to continue from.
//
// assessMining() derives both from raw events: each event's envelope is verified (id, author, signature), the events
// are folded by the same reducers a wallet uses (progression proofs, the burn gate, auto-claims), and what the
// reader could not confirm counts for nothing. The burn records are the READER's: a validator asks Solana itself
// (fetchBurnRecord) and passes the answers in; nothing in an event can make a burn count.
//
// Cost for a validator: one envelope check and one signature per event, plus a few milliseconds per progression
// event (succinct-vdf.js) — not the work the domain did. `baseline` (the wallet state this same validator derived
// earlier, from the events before these) makes it incremental: only the new events are folded.

import { verifyEvent } from './event.js';
import { initialWalletState, materializeWalletFromWireEvents } from './wallet.js';
import { claimableNow, withConfirmedBurns, miningChainHead } from './accrual.js';
import { domainAge } from './reward.js';
import { fromUnits } from './units.js';

/** The mining state of `domain` in `walletState`, or null if it has no position. */
export function miningState(rewardParams, walletState, domain) {
  const position = walletState.accrual.positions[domain];
  if (!position) return null;
  const epoch = domainAge(walletState.accrual.progression, domain);
  const sinceLastAction = Math.max(0, epoch - position.lastActionEpoch);
  const claimableUnits = claimableNow(rewardParams, walletState.accrual, domain);
  return {
    domain,
    capital: position.b,
    T: position.T ?? 0,
    lastActionEpoch: position.lastActionEpoch,
    epoch,
    sinceLastAction,
    chainHead: miningChainHead(walletState.accrual, domain),
    claimableUnits,
    claimable: fromUnits(claimableUnits),
  };
}

/** The ranking figure of a mining state: { score, laps }, with laps >= 1 as in YourMine (the ratio divides by laps + 1). */
export function rankingFigure(mining) {
  if (!mining) return null;
  return { score: Number(mining.claimable), laps: Math.max(1, mining.sinceLastAction), epoch: mining.epoch };
}

function topologicalOrder(events) {
  const byId = new Map(events.map((e) => [e.id, e]));
  const done = new Set();
  const out = [];
  const visit = (event, trail) => {
    if (done.has(event.id) || trail.has(event.id)) return;
    trail.add(event.id);
    for (const parent of event.parents ?? []) {
      const p = byId.get(parent);
      if (p) visit(p, trail);
    }
    trail.delete(event.id);
    done.add(event.id);
    out.push(event);
  };
  for (const event of events) visit(event, new Set());
  return out;
}

/**
 * @param {object} args
 * @param {object} args.rewardParams the deployment's parameters (alpha, beta, gamma, C, minQ, epochIterations, ...)
 * @param {object[]} args.events wire events (any order; events whose envelope does not verify are set aside)
 * @param {object} [args.burnRecords] signature -> record, as fetchBurnRecord returned them: the reader's own
 * @param {string} args.domain the domain being assessed
 * @param {object} [args.baseline] the wallet state this reader derived earlier from the events before `events`
 * @returns {Promise<{ domain: string, mining: object | null, ranking: object | null, burns: { covered: number, consumed: number }, rejections: object[], invalidEvents: string[], state: object }>}
 */
export async function assessMining({ rewardParams, events, burnRecords = {}, domain, baseline }) {
  const valid = [];
  const invalidEvents = [];
  for (const event of events) {
    const check = await verifyEvent(event).catch(() => ({ valid: false }));
    if (check.valid) valid.push(event);
    else invalidEvents.push(event?.id ?? null);
  }
  const start = withConfirmedBurns(baseline ?? initialWalletState(), burnRecords);
  const state = await materializeWalletFromWireEvents(rewardParams, topologicalOrder(valid), null, undefined, {}, start);
  const mining = miningState(rewardParams, state, domain);
  return {
    domain,
    mining,
    ranking: rankingFigure(mining),
    burns: { covered: state.accrual.burns.covered[domain] ?? 0, consumed: state.accrual.burns.consumed?.[domain] ?? 0 },
    rejections: [...state.accrual.progression.rejections, ...state.accrual.rejections, ...state.rejections].filter((r) => !r.domain || r.domain === domain),
    invalidEvents,
    state,
  };
}
