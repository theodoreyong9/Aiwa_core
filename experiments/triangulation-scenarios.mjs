// The weighted median of computeCausalTick and the weight-free triangulation of src/triangulation.js, run on the
// same synthetic worlds. `node experiments/triangulation-scenarios.mjs` prints the table; the test asserts it.
//
// SYNTHETIC: these worlds model the threats we thought of, with fixtures that skip signature checks on the target's
// events (the real EventLog verifies them at append). A result here is a comparison of two rules on chosen
// cases, not a security proof of either.
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '../src/identity.js';
import { initialMirrorState, applyMirrorEvent, deriveSourceEpochLookup } from '../src/mirror.js';
import { initialIdentityCostState, registerIdentityCost } from '../src/identity-cost.js';
import { computeCausalTick, checkCausalConsistency } from '../src/causal-tick.js';
import { triangulate, judgeSelfReport } from '../src/triangulation.js';

const toHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
const canonical = ({ domain, epoch, kind, receivedFrom }) =>
  JSON.stringify({ domain, epoch, kind, receivedFrom: [...receivedFrom].sort((a, b) => (a.sourceDomain + a.eventId).localeCompare(b.sourceDomain + b.eventId)) });

const progression = (id, epoch, parents = []) => ({ id, parents, payload: { type: 'progression', domain: 'target', epoch } });

// observers: [{ burn, cites: [eventId...] }]
async function world(events, observers) {
  let mirror = initialMirrorState();
  let cost = initialIdentityCostState();
  const lookup = deriveSourceEpochLookup(events);
  let n = 0;
  for (const observer of observers) {
    const seed = ed25519.utils.randomSecretKey();
    const pubkey = ed25519.getPublicKey(seed);
    const domain = await deriveId(pubkey);
    if (observer.burn > 0) {
      cost = registerIdentityCost(cost, { domain, tx: { signature: `sig-${domain}`, err: null, incineratorBalanceDeltaLamports: observer.burn, commitment: 'finalized', slot: 1 } }).state;
    }
    const fields = { domain, epoch: 1, kind: 'full', receivedFrom: observer.cites.map((eventId) => ({ sourceDomain: 'target', eventId })) };
    const signature = toHex(ed25519.sign(new TextEncoder().encode(canonical(fields)), seed));
    mirror = await applyMirrorEvent(mirror, { id: `m${++n}`, payload: { type: 'reception', ...fields, signature, signerPubkey: toHex(pubkey) } }, lookup);
  }
  return { mirror, cost };
}

export const SCENARIOS = [
  {
    name: 'honest world',
    truth: 100, selfReport: 100,
    events: () => [progression('e100', 100)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 1000, cites: ['e100'] }, { burn: 1000, cites: ['e100'] }],
  },
  {
    name: 'funded majority saw only an OLD state',
    truth: 100, selfReport: 100,
    events: () => [progression('e10', 10), progression('e100', 100, ['e10'])],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e10'] }, { burn: 10000, cites: ['e10'] }, { burn: 10000, cites: ['e10'] }],
  },
  {
    name: 'unfunded sybils who saw an old state',
    truth: 100, selfReport: 100,
    events: () => [progression('e10', 10), progression('e100', 100, ['e10'])],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 0, cites: ['e10'] }, { burn: 0, cites: ['e10'] }, { burn: 0, cites: ['e10'] }],
  },
  {
    name: 'X rewinds to 50; funded majority saw 50, one honest saw 100',
    truth: 100, selfReport: 50,
    events: () => [progression('e50', 50), progression('e100', 100, ['e50'])],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 10000, cites: ['e50'] }, { burn: 10000, cites: ['e50'] }, { burn: 10000, cites: ['e50'] }],
  },
  {
    name: 'X forks: two unrelated histories at epoch 100',
    truth: 100, selfReport: 100,
    events: () => [progression('base', 90), progression('e100a', 100, ['base']), progression('e100b', 100, ['base'])],
    observers: [{ burn: 1000, cites: ['e100a'] }, { burn: 1000, cites: ['e100b'] }, { burn: 1000, cites: ['e100a'] }],
  },
  {
    name: 'observer cites an event that does not exist',
    truth: 100, selfReport: 100,
    events: () => [progression('e100', 100)],
    observers: [{ burn: 1000, cites: ['e100'] }, { burn: 50000, cites: ['e-invented'] }],
  },
  {
    // The case the existing weighted-median security test uses. The real EventLog verifies an event's signature and
    // proof when it is appended; this fixture models the day that check has a hole. The triangulation trusts the
    // events of X it is given — a forged one FOOLS it. The weight does not.
    name: 'a FORGED epoch-999999 event of X got into the log; 1 adversary cites it',
    truth: 100, selfReport: 100,
    events: () => [progression('e100', 100), progression('e-forged', 999999)],
    observers: [{ burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e100'] }, { burn: 10000, cites: ['e-forged'] }],
  },
  {
    name: 'only stale observers, X progressed offline to 100',
    truth: 100, selfReport: 100,
    events: () => [progression('e10', 10)],
    observers: [{ burn: 1000, cites: ['e10'] }, { burn: 1000, cites: ['e10'] }],
  },
];

export async function runScenarios() {
  const rows = [];
  for (const scenario of SCENARIOS) {
    const events = scenario.events();
    const { mirror, cost } = await world(events, scenario.observers);
    const weighted = await computeCausalTick(mirror, cost, events, 'target');
    const consistency = checkCausalConsistency(scenario.selfReport, weighted, 5);
    const triangulation = triangulate(mirror, events, 'target');
    const judged = judgeSelfReport(scenario.selfReport, triangulation);
    rows.push({ name: scenario.name, truth: scenario.truth, selfReport: scenario.selfReport, weighted, consistency, triangulation, judged });
  }
  return rows;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = await runScenarios();
  const pad = (s, n) => String(s).padEnd(n);
  console.log(pad('scenario', 60), pad('truth', 6), pad('self', 5), pad('weighted tick', 14), pad('consistent?', 12), pad('lower bound', 12), pad('contradicted', 13), pad('forked', 7), 'ahead');
  for (const r of rows) {
    console.log(pad(r.name, 60), pad(r.truth, 6), pad(r.selfReport, 5), pad(r.weighted ? r.weighted.tick : '⊥', 14), pad(r.consistency.consistent, 12),
      pad(r.triangulation ? r.triangulation.lowerBound : '⊥', 12), pad(r.judged.contradicted, 13), pad(r.judged.forked, 7), r.judged.ahead);
  }
}
