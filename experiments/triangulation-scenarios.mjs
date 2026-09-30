// Three rules on the same synthetic worlds:
//   weighted   — computeCausalTick's weighted median, and its consistency check (the status quo)
//   triangulate— src/triangulation.js with the log trusted (no authenticity check): proofs alone
//   combined   — src/position.js: proofs for the floor and the accusations, the median as the estimate,
//                every progression event of the target re-checked first
// `node experiments/triangulation-scenarios.mjs` prints the table; test/triangulation.test.mjs asserts it.
//
// SYNTHETIC: worlds modelling the threats we thought of. The target's events are really signed; observers'
// commitments are really signed and applied through applyMirrorEvent; "burn" is registered through
// registerIdentityCost. A result is a comparison of rules on chosen cases, not a security proof of any.
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '../src/identity.js';
import { initialMirrorState, applyMirrorEvent, deriveSourceEpochLookup } from '../src/mirror.js';
import { initialIdentityCostState, registerIdentityCost } from '../src/identity-cost.js';
import { computeCausalTick, checkCausalConsistency } from '../src/causal-tick.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { triangulate, judgeSelfReport } from '../src/triangulation.js';
import { assessPosition } from '../src/position.js';

const toHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
const canonical = ({ domain, epoch, kind, receivedFrom }) =>
  JSON.stringify({ domain, epoch, kind, receivedFrom: [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId)) });

async function keypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkey = ed25519.getPublicKey(seed);
  return { seed, pubkey, domain: await deriveId(pubkey) };
}

// A progression event of `target`, really signed by `signer` (the target itself, or a forger).
async function progression(target, signer, id, epoch, parents = []) {
  const signed = await buildSignedProgressionEvent({ domain: target.domain, epoch, vdfIterations: 1, vdfOutput: `out-${epoch}` }, signer.seed, signer.pubkey);
  return { id, parents, payload: { type: 'progression', ...signed } };
}

// observers: [{ burn, cites: [eventId...] }]
async function world(target, events, observers) {
  let mirror = initialMirrorState();
  let cost = initialIdentityCostState();
  const lookup = deriveSourceEpochLookup(events);
  let n = 0;
  for (const observer of observers) {
    const who = await keypair();
    if (observer.burn > 0) {
      cost = registerIdentityCost(cost, { domain: who.domain, tx: { signature: `sig-${who.domain}`, err: null, incineratorBalanceDeltaLamports: observer.burn, commitment: 'finalized', slot: 1 } }).state;
    }
    const fields = { domain: who.domain, epoch: 1, kind: 'full', receivedFrom: observer.cites.map((eventId) => ({ sourceDomain: target.domain, eventId })) };
    const signature = toHex(ed25519.sign(new TextEncoder().encode(canonical(fields)), who.seed));
    mirror = await applyMirrorEvent(mirror, { id: `m${++n}`, payload: { type: 'reception', ...fields, signature, signerPubkey: toHex(who.pubkey) } }, lookup);
  }
  return { mirror, cost };
}

export const SCENARIOS = [
  {
    name: 'honest world',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e100', 100)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 1000, cites: ['e100'] }, { burn: 1000, cites: ['e100'] }],
  },
  {
    name: 'funded majority saw only an OLD state (10); one honest saw 100',
    selfReport: 100,
    events: async (t) => { const e10 = await progression(t, t, 'e10', 10); return [e10, await progression(t, t, 'e100', 100, ['e10'])]; },
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e10'] }, { burn: 10000, cites: ['e10'] }, { burn: 10000, cites: ['e10'] }],
  },
  {
    name: 'unfunded observers who saw an old state',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e10', 10), await progression(t, t, 'e100', 100, ['e10'])],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 0, cites: ['e10'] }, { burn: 0, cites: ['e10'] }, { burn: 0, cites: ['e10'] }],
  },
  {
    name: 'ONLY unfunded observers, all saw 100',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e100', 100)],
    observers: [{ burn: 0, cites: ['e100'] }, { burn: 0, cites: ['e100'] }],
  },
  {
    name: 'X rewinds to 50; funded majority saw 50; one honest saw 100',
    selfReport: 50,
    events: async (t) => [await progression(t, t, 'e50', 50), await progression(t, t, 'e100', 100, ['e50'])],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e50'] }, { burn: 10000, cites: ['e50'] }, { burn: 10000, cites: ['e50'] }],
  },
  {
    name: 'X holds two unrelated histories at epoch 100',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'base', 90), await progression(t, t, 'e100a', 100, ['base']), await progression(t, t, 'e100b', 100, ['base'])],
    observers: [{ burn: 1000, cites: ['e100a'] }, { burn: 1000, cites: ['e100b'] }, { burn: 1000, cites: ['e100a'] }],
  },
  {
    name: 'observer cites an event that does not exist',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e100', 100)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 50000, cites: ['e-invented'] }],
  },
  {
    name: 'only stale observers; X progressed offline to 100',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e10', 10)],
    observers: [{ burn: 1000, cites: ['e10'] }, { burn: 1000, cites: ['e10'] }],
  },
  {
    // An event attributed to X but signed by someone else got into the log (the day admission has a hole).
    name: 'FORGED epoch-999999 event in the log; a funded MINORITY cites it',
    selfReport: 100,
    events: async (t, forger) => [await progression(t, t, 'e100', 100), await progression(t, forger, 'e-forged', 999999)],
    observers: [{ burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e-forged'] }],
  },
  {
    name: 'FORGED epoch-999999 event in the log; a funded MAJORITY cites it',
    selfReport: 100,
    events: async (t, forger) => [await progression(t, t, 'e100', 100), await progression(t, forger, 'e-forged', 999999)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e-forged'] }, { burn: 10000, cites: ['e-forged'] }, { burn: 10000, cites: ['e-forged'] }],
  },
  {
    // NOT covered: the target signs a far-ahead event itself, without doing the sequential work. The signature is
    // genuine, so a signature-only authenticity check accepts it. Admission (applyProgressionEvent) checks the VDF;
    // a caller that wants it here passes a stricter `isAuthentic`.
    name: 'X SIGNS a fake far-ahead event itself (no sequential work); a funded majority cites it',
    selfReport: 100,
    events: async (t) => [await progression(t, t, 'e100', 100), await progression(t, t, 'e-self-fake', 999999)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e-self-fake'] }, { burn: 10000, cites: ['e-self-fake'] }, { burn: 10000, cites: ['e-self-fake'] }],
  },
];

export async function runScenarios() {
  const rows = [];
  for (const scenario of SCENARIOS) {
    const target = await keypair();
    const forger = await keypair();
    const events = await scenario.events(target, forger);
    const { mirror, cost } = await world(target, events, scenario.observers);

    const weightedTick = await computeCausalTick(mirror, cost, events, target.domain);
    const weighted = { tick: weightedTick ? weightedTick.tick : null, consistent: checkCausalConsistency(scenario.selfReport, weightedTick, 5).consistent };

    const trusted = await triangulate(mirror, events, target.domain, { isAuthentic: async () => true });
    const trustedJudged = judgeSelfReport(scenario.selfReport, trusted);
    const triang = { lowerBound: trusted ? trusted.lowerBound : null, contradicted: trustedJudged.contradicted, forked: trustedJudged.forked };

    const combined = await assessPosition({ mirrorState: mirror, identityCostState: cost, orderedEvents: events, targetDomain: target.domain, selfReportedEpoch: scenario.selfReport });
    rows.push({ name: scenario.name, selfReport: scenario.selfReport, weighted, triang, combined });
  }
  return rows;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = await runScenarios();
  const show = (v) => (v === null || v === undefined ? '⊥' : String(v));
  const pad = (s, n) => String(s).padEnd(n);
  console.log(pad('world', 70), pad('self', 5), '| WEIGHTED tick ok? ', '| TRIANGULATE (log trusted) bound acc? ', '| COMBINED position accuse');
  for (const r of rows) {
    console.log(pad(r.name, 70), pad(r.selfReport, 5),
      '|', pad(show(r.weighted.tick), 10), pad(r.weighted.consistent ? 'yes' : 'NO', 4),
      '|', pad(show(r.triang.lowerBound), 8), pad(r.triang.contradicted || r.triang.forked ? 'YES' : 'no', 4),
      '|', pad(show(r.combined.position), 9), r.combined.accuse ? `YES (${r.combined.contradicted ? 'rewind' : 'fork'})` : 'no');
  }
}
