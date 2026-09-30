// Three rules on the same synthetic worlds:
//   weighted   — computeCausalTick's weighted median, and its consistency check (the status quo)
//   triangulate— src/triangulation.js with the log trusted (no authenticity check): proofs alone
//   combined   — src/position.js (assessPosition, default settings): proofs for the floor and the accusations,
//                the median as the estimate, the target's progression events replayed through the real reducer
//                first when the reader holds them from epoch 1
// `node experiments/triangulation-scenarios.mjs` prints the table; test/triangulation.test.mjs asserts it.
//
// SYNTHETIC: worlds modelling the threats we thought of. The target's progression events are a real chain
// (signed, chained, real sequential proofs of 3 iterations); observers' commitments are really signed and applied
// through applyMirrorEvent; "burn" is registered through registerIdentityCost. A result is a comparison of rules
// on chosen cases, not a security proof of any.
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '../src/identity.js';
import { initialMirrorState, applyMirrorEvent, deriveSourceEpochLookup } from '../src/mirror.js';
import { initialIdentityCostState, registerIdentityCost } from '../src/identity-cost.js';
import { computeCausalTick, checkCausalConsistency } from '../src/causal-tick.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { triangulate, judgeSelfReport } from '../src/triangulation.js';
import { assessPosition } from '../src/position.js';

const toHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
const canonical = ({ domain, epoch, kind, receivedFrom }) =>
  JSON.stringify({ domain, epoch, kind, receivedFrom: [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId)) });
const ITERATIONS = 3;

export async function keypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkey = ed25519.getPublicKey(seed);
  return { seed, pubkey, domain: await deriveId(pubkey) };
}

// One progression event of `target`, really signed by `signer` (the target itself, or a forger), with a REAL
// sequential proof chained from `previous` (or from genesis) unless `vdfOutput` says otherwise.
export async function link(target, signer, id, epoch, previous, { vdfOutput } = {}) {
  const output = vdfOutput ?? await computeVdfChain(vdfSeed(target.domain, previous ? previous.payload.vdfOutput : 'genesis'), ITERATIONS);
  const signed = await buildSignedProgressionEvent({ domain: target.domain, epoch, vdfIterations: ITERATIONS, vdfOutput: output }, signer.seed, signer.pubkey);
  return { id, parents: previous ? [previous.id] : [], payload: { type: 'progression', ...signed } };
}

// The target's honest chain e{from}..e{to}; a reader that holds only a part starts at `from` (no genesis).
export async function honestChain(target, to, from = 1) {
  const events = [];
  let previous = null;
  for (let epoch = 1; epoch <= to; epoch++) {
    previous = await link(target, target, `e${epoch}`, epoch, previous);
    if (epoch >= from) events.push(previous);
  }
  return events;
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

const f = (burn, ...cites) => ({ burn, cites });

export const SCENARIOS = [
  { name: 'honest world', selfReport: 20,
    events: async (t) => honestChain(t, 20),
    observers: [f(1000, 'e20'), f(1000, 'e20'), f(1000, 'e20')] },
  { name: 'funded majority saw only an OLD state (4); one honest saw 20', selfReport: 20,
    events: async (t) => honestChain(t, 20),
    observers: [f(1000, 'e20'), f(10000, 'e4'), f(10000, 'e4'), f(10000, 'e4')] },
  { name: 'unfunded observers who saw an old state', selfReport: 20,
    events: async (t) => honestChain(t, 20),
    observers: [f(1000, 'e20'), f(0, 'e4'), f(0, 'e4'), f(0, 'e4')] },
  { name: 'ONLY unfunded observers, all saw 20', selfReport: 20,
    events: async (t) => honestChain(t, 20),
    observers: [f(0, 'e20'), f(0, 'e20')] },
  { name: 'X rewinds to 10; funded majority saw 10; one honest saw 20', selfReport: 10,
    events: async (t) => honestChain(t, 20),
    observers: [f(1000, 'e20'), f(10000, 'e10'), f(10000, 'e10'), f(10000, 'e10')] },
  { name: 'X holds two unrelated histories at epoch 21', selfReport: 21,
    events: async (t) => {
      const chain = await honestChain(t, 20);
      return [...chain, await link(t, t, 'e21a', 21, chain[19]), await link(t, t, 'e21b', 21, chain[19])];
    },
    observers: [f(1000, 'e21a'), f(1000, 'e21b'), f(1000, 'e21a')] },
  { name: 'observer cites an event that does not exist', selfReport: 20,
    events: async (t) => honestChain(t, 20),
    observers: [f(1000, 'e20'), f(50000, 'e-invented')] },
  { name: 'only stale observers; X progressed offline to 20', selfReport: 20,
    events: async (t) => honestChain(t, 4),
    observers: [f(1000, 'e4'), f(1000, 'e4')] },
  { // An event attributed to X but signed by someone else got into the log (the day admission has a hole).
    name: 'FORGED epoch-999999 event (signed by someone else); a funded MINORITY cites it', selfReport: 20,
    events: async (t, forger) => { const chain = await honestChain(t, 20); return [...chain, await link(t, forger, 'e-forged', 999999, chain[19])]; },
    observers: [f(10000, 'e20'), f(10000, 'e20'), f(10000, 'e20'), f(10000, 'e-forged')] },
  { name: 'FORGED epoch-999999 event (signed by someone else); a funded MAJORITY cites it', selfReport: 20,
    events: async (t, forger) => { const chain = await honestChain(t, 20); return [...chain, await link(t, forger, 'e-forged', 999999, chain[19])]; },
    observers: [f(1000, 'e20'), f(10000, 'e-forged'), f(10000, 'e-forged'), f(10000, 'e-forged')] },
  { // The signature is genuine; the sequential work is not there. Anyone who replays the chain rejects it.
    name: 'X SIGNS a fake far-ahead event itself (no sequential work); a funded majority cites it', selfReport: 20,
    events: async (t) => { const chain = await honestChain(t, 20); return [...chain, await link(t, t, 'e-self-fake', 999999, chain[19], { vdfOutput: 'f'.repeat(64) })]; },
    observers: [f(1000, 'e20'), f(10000, 'e-self-fake'), f(10000, 'e-self-fake'), f(10000, 'e-self-fake')] },
  { // The reader holds epochs 15..20 only: nothing can be chained, so the check falls back to the signature.
    name: 'same, but the reader holds only epochs 15-20 (no genesis): the chain cannot be replayed', selfReport: 20,
    events: async (t) => { const chain = await honestChain(t, 20, 15); const full = await honestChain(t, 20); return [...chain, await link(t, t, 'e-self-fake', 999999, full[19], { vdfOutput: 'f'.repeat(64) })]; },
    observers: [f(1000, 'e20'), f(10000, 'e-self-fake'), f(10000, 'e-self-fake'), f(10000, 'e-self-fake')] },
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
  console.log(pad('world', 96), pad('self', 5), '| WEIGHTED tick ok? ', '| TRIANGULATE (log trusted) bound acc? ', '| COMBINED position accuse       check');
  for (const r of rows) {
    console.log(pad(r.name, 96), pad(r.selfReport, 5),
      '|', pad(show(r.weighted.tick), 10), pad(r.weighted.consistent ? 'yes' : 'NO', 4),
      '|', pad(show(r.triang.lowerBound), 8), pad(r.triang.contradicted || r.triang.forked ? 'YES' : 'no', 4),
      '|', pad(show(r.combined.position), 9), pad(r.combined.accuse ? `YES (${r.combined.contradicted ? 'rewind' : 'fork'})` : 'no', 12), r.combined.verification);
  }
}
