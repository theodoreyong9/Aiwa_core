// Mining evidence a wallet hands to an app — a registry, a leaderboard, anything that must rank or pay by a domain's
// mining without trusting the wallet — and what the app does with it. Turnkey: an app keeps its own storage and
// policy (what a figure is worth, who may publish), and gets the protocol part from here.
//
//   evidence    { version, domain, afterEpoch, events, witnesses }   (aiwa-lib: wallet.submissionEvidence())
//   baseline    { domain, epoch, head, state }    what the app derived for this domain last time, kept as is
//   witnessed   [{ id, epoch }]                   what other wallets hold of this domain (see below)
//
//   assessSubmission(...)    verifies the evidence and derives the mining state (assessMining) — burns confirmed by
//                            THIS reader, chained from the baseline — and checks the witnesses.
//   ingestWitnesses(...)     which of the witnesses a submission brings about OTHER domains are worth keeping.
//   mergeWitnessStore(...)   the store with those added, bounded, and what has since been validated dropped.
//
// WHY WITNESSES. The mining events of a domain are one signed chain (accrual.js): an action cannot be left out of a
// history, and proven work cannot be re-signed over another one for free. That is not "no second history": a domain
// can keep two, redoing the work, and show only the favourable one. Someone else holding the other closes it: a
// wallet that received a domain's events can show the highest progression event of it that it holds — SIGNED BY THAT
// DOMAIN, which is what makes it a proof, with no trust in whoever shows it. The app keeps it, and when the domain
// next submits, the history shown must contain it. A fork, a stretch of work cut short, or a hidden action followed
// by more work is then refused.
//
// What it does not give. A witness exists only if someone received those events. A burn made after the last epoch
// shown and followed by none can still be left out: a submission is a snapshot, not "the current state" (that needs
// a clock — e.g. the head anchored on Solana). A domain whose history was really forked (one key, two devices) is
// refused for good once its other history is witnessed.

import { assessMining } from './mining-state.js';
import { fetchBurnRecord, base58Decode } from './burn-record.js';
import { serializeWalletState, deserializeWalletState } from './checkpoint.js';
import { verifyEvent } from './event.js';
import { signatureAuthentic } from './triangulation.js';
import { deriveId } from './identity.js';

export const SUBMISSION_LIMITS = {
  events: 200_000,            // one submission's evidence
  burns: 200,                 // burn records one submission may ask the reader to confirm
  witnessesPerSubmission: 50,
  witnessesPerDomain: 32,     // what an app keeps per domain (the furthest along)
  witnessBytes: 16_384,       // one witness event
};

/** The Aiwa domain of a Solana address: the hash of the key (a wallet and its domain are the same key). */
export async function domainOfAddress(address) {
  return deriveId(base58Decode(address));
}

/**
 * @param {object} args
 * @param {object} args.rewardParams the deployment's parameters (must set epochIterations: the chain is its rule)
 * @param {object} args.evidence { version, domain, afterEpoch, events, witnesses }
 * @param {string} args.domain the domain the app expects the evidence to be for
 * @param {object|null} [args.baseline] what this app derived for the domain before: { domain, epoch, head, state }
 * @param {Array<{ id: string, epoch: number }>} [args.witnessed] what others hold of this domain (kept by the app)
 * @param {{ getTransaction: Function }} [args.connection] Solana — needed only to confirm burns the baseline did not count
 * @returns {Promise<{ ok: boolean, reason: string, mining: object|null, ranking: object|null, rejections: object[], baseline: object|null }>}
 *   `ok` is false when the evidence cannot be used at all (shape, domain, continuity, limits, a witness missing);
 *   `ok` with `mining: null` means a valid history with no position (no confirmed burn, nothing committed). `baseline`
 *   is what to keep for the next submission of this domain.
 */
export async function assessSubmission({ rewardParams, evidence, domain, baseline = null, witnessed = [], connection, limits = SUBMISSION_LIMITS }) {
  const no = (reason, extra = {}) => ({ ok: false, reason, mining: null, ranking: null, rejections: [], baseline: null, ...extra });
  if (!evidence || typeof evidence !== 'object' || !Array.isArray(evidence.events)) return no('No evidence with this submission');
  if (evidence.domain !== domain) return no('The evidence is not for this domain');
  if (evidence.events.length > limits.events) return no('Too many events in the evidence');

  // The reader's own earlier derivation is the base — but only if the evidence continues exactly from it.
  const after = Number.isInteger(evidence.afterEpoch) ? evidence.afterEpoch : 0;
  let base;
  if (after > 0) {
    if (!baseline || baseline.domain !== domain || baseline.epoch !== after) {
      return no(`The evidence continues from epoch ${after}; this reader holds epoch ${baseline ? baseline.epoch : 'none'} for this domain`);
    }
    base = deserializeWalletState(baseline.state);
  }

  // Burns: asked of Solana by THIS reader, for the signatures the domain's own burn-record events point at — except
  // the ones the baseline already counted.
  const counted = base?.accrual?.burns?.used ?? {};
  const wanted = [...new Set(evidence.events
    .filter((e) => e && e.type === 'burn-record' && e.author === domain && typeof e.payload?.signature === 'string')
    .map((e) => e.payload.signature))].filter((signature) => !counted[signature]);
  if (wanted.length > limits.burns) return no('Too many burns to confirm in one submission');
  if (wanted.length > 0 && !connection) throw new Error('assessSubmission: a connection (Solana) is needed to confirm the burns the evidence points at');
  const burnRecords = {};
  for (const signature of wanted) {
    const record = await fetchBurnRecord(connection, signature).catch(() => null);
    if (record) burnRecords[signature] = record;
  }

  const result = await assessMining({ rewardParams, events: evidence.events, burnRecords, domain, baseline: base });

  // What others hold of this domain, beyond the baseline, must be in the history shown — and accepted by it.
  const refused = new Set([...result.rejections.map((r) => r.eventId), ...result.invalidEvents]);
  const shown = new Set(evidence.events.map((e) => e && e.id));
  for (const w of witnessed) {
    if (!(w && typeof w.id === 'string' && w.epoch > after)) continue;   // before the baseline: the reader already moved past it
    if (!shown.has(w.id) || refused.has(w.id)) {
      return no(`Another holder of this domain's events has its progression event ${w.id.slice(0, 12)}… (epoch ${w.epoch}); the history shown does not contain it`, { mining: result.mining, rejections: result.rejections });
    }
  }

  if (!result.mining) return { ok: true, reason: 'No position: no confirmed burn, or nothing committed', mining: null, ranking: null, rejections: result.rejections, baseline: null };
  return {
    ok: true, reason: 'ok', mining: result.mining, ranking: result.ranking, rejections: result.rejections,
    baseline: { domain, epoch: result.mining.epoch, head: result.mining.chainHead, state: serializeWalletState(result.state) },
  };
}

/**
 * Which of the witnesses a submission carries an app should keep. A witness is an event another domain signed, held
 * by the submitter. It is kept only if it is a progression event of a domain other than the submitter's, whose
 * envelope and own signature verify, and that goes beyond what the app already validated for that domain. Anything
 * else is ignored — never a reason to refuse the submission.
 * @param {object} args
 * @param {object[]} args.witnesses the wire events the submission brought
 * @param {string} args.ownDomain the submitter's domain
 * @param {(domain: string) => number} [args.baselineEpochOf] the epoch the app validated for a domain (0 if none)
 * @returns {Promise<{ accepted: Array<{ domain: string, id: string, epoch: number }>, ignored: number }>}
 */
export async function ingestWitnesses({ witnesses, ownDomain, baselineEpochOf = () => 0, limits = SUBMISSION_LIMITS }) {
  const accepted = [];
  let ignored = 0;
  if (!Array.isArray(witnesses)) return { accepted, ignored };
  const seen = new Set();
  for (const w of witnesses.slice(0, limits.witnessesPerSubmission)) {
    try {
      if (!w || w.type !== 'progression' || !w.payload || JSON.stringify(w).length > limits.witnessBytes) throw new Error('shape');
      const domain = w.payload.domain;
      if (typeof domain !== 'string' || domain !== w.author || domain === ownDomain) throw new Error('domain');
      if (!Number.isInteger(w.payload.epoch) || w.payload.epoch < 1) throw new Error('epoch');
      if (w.payload.epoch <= baselineEpochOf(domain)) throw new Error('already validated');
      if (seen.has(w.id)) throw new Error('duplicate');
      if (!(await verifyEvent(w)).valid || !(await signatureAuthentic(w))) throw new Error('signature');
      seen.add(w.id);
      accepted.push({ domain, id: w.id, epoch: w.payload.epoch });
    } catch { ignored++; }
  }
  return { accepted, ignored };
}

/**
 * The witness store (domain -> [{ id, epoch }]) with `accepted` added: at most `witnessesPerDomain` per domain (the
 * furthest along), and what the app has validated since dropped (the history that passed it contained them).
 */
export function mergeWitnessStore(store, accepted, baselineEpochOf = () => 0, limits = SUBMISSION_LIMITS) {
  const next = {};
  const byDomain = {};
  for (const [domain, list] of Object.entries(store ?? {})) byDomain[domain] = [...list];
  for (const w of accepted) (byDomain[w.domain] ??= []).push({ id: w.id, epoch: w.epoch });
  for (const [domain, list] of Object.entries(byDomain)) {
    const floor = baselineEpochOf(domain);
    const unique = new Map();
    for (const w of list) if (w.epoch > floor) unique.set(w.id, { id: w.id, epoch: w.epoch });
    const kept = [...unique.values()].sort((a, b) => b.epoch - a.epoch).slice(0, limits.witnessesPerDomain);
    if (kept.length > 0) next[domain] = kept;
  }
  return next;
}
