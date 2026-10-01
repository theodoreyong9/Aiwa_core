import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity } from '../src/identity.js';
import { createEvent } from '../src/event.js';
import { vdfSeed } from '../src/vdf.js';
import { computeSuccinctEpochs } from '../src/succinct-vdf.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { buildSignedAccrualEvent, buildSignedClaimEvent } from '../src/accrual.js';
import { normalizeBurnTransaction } from '../src/burn-record.js';
import { SOLANA_INCINERATOR_ADDRESS } from '../src/identity-cost.js';
import { assessMining, miningState, rankingFigure } from '../src/mining-state.js';
import { serializeWalletState, deserializeWalletState } from '../src/checkpoint.js';

// What a validator does with a domain's events: derive the mining state and the ranking figure, trusting nothing the
// domain says — not its age, not its burn, not its score.
const EI = 120;
const params = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1, epochIterations: EI };

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(hex) {
  let x = BigInt('0x' + hex);
  let out = '';
  while (x > 0n) { out = ALPHABET[Number(x % 58n)] + out; x /= 58n; }
  return out;
}
const burnRecord = (who, lamports, signature) => normalizeBurnTransaction({
  slot: 9,
  transaction: { message: { accountKeys: [base58(who.publicKey), SOLANA_INCINERATOR_ADDRESS] } },
  meta: { err: null, fee: 5000, preBalances: [50e9, 0], postBalances: [50e9 - lamports - 5000, lamports] },
}, signature);

// a domain's honest history, as wire events: { id, ... } in the order they were made
async function history(who, steps) {
  const events = [];
  let head = [];
  let vdfOutput = null;
  let epoch = 0;
  let lastProgression = null;
  const append = async (type, payload) => {
    const parents = type === 'progression' && lastProgression && !head.includes(lastProgression) ? [...head, lastProgression] : head;
    const e = await createEvent(who, { domain: `log:${who.id}`, parents, type, payload });
    events.push(e);
    head = [e.id];
    if (type === 'progression') lastProgression = e.id;
    return e;
  };
  for (const step of steps) {
    if (step.burn) await append('burn-record', { domain: who.id, signature: step.burn });
    if (step.epochs) {
      const iterations = step.epochs * EI;
      const work = await computeSuccinctEpochs(vdfSeed(who.id, vdfOutput ?? 'genesis'), iterations);
      epoch += step.epochs;
      const signed = await buildSignedProgressionEvent({ domain: who.id, epoch, vdfIterations: iterations, vdfOutput: work.vdfOutput }, secretOf(who), who.publicKeyBytes);
      await append('progression', { ...signed, vdfProof: work.vdfProof });
      vdfOutput = work.vdfOutput;
    }
    if (step.commit) {
      const signed = await buildSignedAccrualEvent({ domain: who.id, ...step.commit }, secretOf(who), who.publicKeyBytes);
      await append('accrual', signed);
    }
    if (step.claim) {
      const signed = await buildSignedClaimEvent({ domain: who.id, claimId: step.claim.claimId, amount: step.claim.amount }, secretOf(who), who.publicKeyBytes);
      await append('claim', signed);
    }
  }
  return events;
}
const secretOf = (who) => who.secretKeyBytes;

async function person() {
  const who = await generateIdentity();
  who.secretKeyBytes = Uint8Array.from(Buffer.from(who.secretKey ?? who._secretKey ?? '', 'hex'));
  who.publicKeyBytes = Uint8Array.from(Buffer.from(who.publicKey, 'hex'));
  return who;
}

test('the mining state and the ranking figure come out of the events alone', async () => {
  const a = await person();
  const events = await history(a, [{ burn: 'sig1' }, { epochs: 2 }, { commit: { b: 1, T: 0.2 } }, { epochs: 6 }]);
  const result = await assessMining({ rewardParams: params, events, burnRecords: { sig1: burnRecord(a, 2_000_000_000, 'sig1') }, domain: a.id });
  assert.deepEqual(result.rejections, []);
  assert.equal(result.mining.capital, 1);
  assert.equal(result.mining.T, 0.2);
  assert.equal(result.mining.epoch, 8, 'age: the epochs the domain really did');
  assert.equal(result.mining.sinceLastAction, 6);
  assert.ok(Number(result.mining.claimable) > 0);
  assert.equal(result.ranking.laps, 6);
  assert.equal(result.ranking.score, Number(result.mining.claimable));
  assert.equal(result.burns.covered, 2_000_000_000);
  assert.ok(result.burns.consumed >= 1_000_000_000);
});

test('events given in any order, or with one the domain forged, give the same answer for the honest part', async () => {
  const a = await person();
  const events = await history(a, [{ burn: 's' }, { epochs: 3 }, { commit: { b: 1 } }, { epochs: 4 }]);
  const records = { s: burnRecord(a, 1_000_000_000, 's') };
  const straight = await assessMining({ rewardParams: params, events, burnRecords: records, domain: a.id });
  const shuffled = await assessMining({ rewardParams: params, events: [...events].reverse(), burnRecords: records, domain: a.id });
  assert.equal(shuffled.mining.claimable, straight.mining.claimable);

  const forged = { ...events[1], payload: { ...events[1].payload, epoch: 999 } }; // tampered after it was signed
  const withForgery = await assessMining({ rewardParams: params, events: [...events, forged], burnRecords: records, domain: a.id });
  assert.deepEqual(withForgery.invalidEvents, [forged.id]);
  assert.equal(withForgery.mining.epoch, straight.mining.epoch);
});

test('a burn the validator did not confirm gives no position, whatever the domain says', async () => {
  const a = await person();
  const events = await history(a, [{ burn: 'sig1' }, { epochs: 2 }, { commit: { b: 5 } }, { epochs: 5 }]);
  const result = await assessMining({ rewardParams: params, events, burnRecords: {}, domain: a.id });
  assert.equal(result.mining, null);
  assert.match(result.rejections.map((r) => r.reason).join('|'), /not covered by a confirmed burn|not confirmed by this reader/);
});

test('age cannot be claimed without the work: an epoch of fewer iterations than the deployment fixes counts for nothing', async () => {
  const a = await person();
  const events = await history(a, [{ burn: 's' }, { epochs: 2 }, { commit: { b: 1 } }]);
  // a lazy epoch: announced as 50 more, with the work of 1
  const work = await computeSuccinctEpochs(vdfSeed(a.id, events.find((e) => e.type === 'progression').payload.vdfOutput), EI);
  const signed = await buildSignedProgressionEvent({ domain: a.id, epoch: 52, vdfIterations: EI, vdfOutput: work.vdfOutput }, a.secretKeyBytes, a.publicKeyBytes);
  const last = events.at(-1);
  const lazy = await createEvent(a, { domain: `log:${a.id}`, parents: [last.id, events.find((e) => e.type === 'progression').id], type: 'progression', payload: { ...signed, vdfProof: work.vdfProof } });
  const result = await assessMining({ rewardParams: params, events: [...events, lazy], burnRecords: { s: burnRecord(a, 1_000_000_000, 's') }, domain: a.id });
  assert.equal(result.mining.epoch, 2, 'the age is what the work proves');
  assert.ok(result.rejections.length > 0);
});

test('incremental: a validator that kept its earlier state only folds the new events', async () => {
  const a = await person();
  const all = await history(a, [{ burn: 's' }, { epochs: 2 }, { commit: { b: 1 } }, { epochs: 3 }, { epochs: 4 }]);
  const records = { s: burnRecord(a, 1_000_000_000, 's') };
  const first = await assessMining({ rewardParams: params, events: all.slice(0, 4), burnRecords: records, domain: a.id });
  const stored = serializeWalletState(first.state); // what the validator keeps
  const later = await assessMining({ rewardParams: params, events: all.slice(4), burnRecords: records, domain: a.id, baseline: deserializeWalletState(stored) });
  const whole = await assessMining({ rewardParams: params, events: all, burnRecords: records, domain: a.id });
  assert.equal(later.mining.epoch, whole.mining.epoch);
  assert.equal(later.mining.claimable, whole.mining.claimable);
});

test('a second burn pays the first one: the claimable is not lost, and the ranking restarts', async () => {
  const a = await person();
  const events = await history(a, [{ burn: 's1' }, { burn: 's2' }, { epochs: 2 }, { commit: { b: 1 } }, { epochs: 6 }, { commit: { b: 1 } }]);
  const records = { s1: burnRecord(a, 1_000_000_000, 's1'), s2: burnRecord(a, 1_000_000_000, 's2') };
  const result = await assessMining({ rewardParams: params, events, burnRecords: records, domain: a.id });
  assert.deepEqual(result.rejections, []);
  assert.equal(result.mining.sinceLastAction, 0);
  assert.equal(rankingFigure(result.mining).laps, 1, 'laps never drop below 1');
  const claimed = Object.values(result.state.conservation.claims).filter((c) => c.owner === a.id);
  assert.equal(claimed.length, 1, 'the first burn was paid out as a claim');
});

test('miningState is null for a domain with no position', () => {
  assert.equal(miningState(params, { accrual: { positions: {}, progression: { domains: {} } } }, 'nobody'), null);
  assert.equal(rankingFigure(null), null);
});
