import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity } from '../src/identity.js';
import { createEvent } from '../src/event.js';
import { computeSuccinctEpochs } from '../src/succinct-vdf.js';
import { buildSignedProgressionEvent, progressionSeed } from '../src/progression.js';
import { buildSignedAccrualEvent } from '../src/accrual.js';
import { SOLANA_INCINERATOR_ADDRESS } from '../src/identity-cost.js';
import { assessSubmission, ingestWitnesses, mergeWitnessStore, domainOfAddress } from '../src/submission.js';

// What an app does with the evidence a wallet hands it — a registry, a leaderboard — with nothing of its own but
// storage: the evidence is verified, the burns are the reader's, the baseline is continued, and what OTHER wallets hold
// of this one must be in the history shown.
const EI = 100;
const params = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1, epochIterations: EI };

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(hex) {
  let x = BigInt('0x' + hex);
  let out = '';
  while (x > 0n) { out = ALPHABET[Number(x % 58n)] + out; x /= 58n; }
  return out;
}
async function person() {
  const who = await generateIdentity();
  who.secretKeyBytes = Uint8Array.from(Buffer.from(who.secretKey ?? who._secretKey ?? '', 'hex'));
  who.publicKeyBytes = Uint8Array.from(Buffer.from(who.publicKey, 'hex'));
  who.address = base58(who.publicKey);
  return who;
}
// Solana, as far as a reader asks: the finalized transaction of a burn. `asked` counts the questions.
function solana(known) {
  const connection = {
    asked: [],
    getTransaction: async (signature) => {
      connection.asked.push(signature);
      const burn = known[signature];
      if (!burn) return null;
      return {
        slot: 5,
        transaction: { message: { accountKeys: [burn.payer, SOLANA_INCINERATOR_ADDRESS, '11111111111111111111111111111111'] } },
        meta: { err: null, fee: 5000, preBalances: [50e9, 0, 1], postBalances: [50e9 - burn.lamports - 5000, burn.lamports, 1] },
      };
    },
  };
  return connection;
}

// a wallet's history, as a wallet builds it
class History {
  constructor(who) { this.who = who; this.events = []; this.parents = []; this.epoch = 0; this.output = null; this.head = null; }
  async append(type, payload) {
    const e = await createEvent(this.who, { domain: 'app', parents: this.parents, type, payload });
    this.events.push(e); this.parents = [e.id];
    if (type === 'progression' || type === 'accrual' || type === 'claim') this.head = e.id;
    return e;
  }
  burn(signature) { return this.append('burn-record', { domain: this.who.id, signature }); }
  async work(epochs) {
    const previous = this.head;
    const w = await computeSuccinctEpochs(progressionSeed(this.who.id, this.output, previous), epochs * EI);
    this.epoch += epochs;
    const signed = await buildSignedProgressionEvent({ domain: this.who.id, epoch: this.epoch, vdfIterations: epochs * EI, vdfOutput: w.vdfOutput, previous }, this.who.secretKeyBytes, this.who.publicKeyBytes);
    this.output = w.vdfOutput;
    return this.append('progression', { ...signed, vdfProof: w.vdfProof });
  }
  async commit(fields) { return this.append('accrual', await buildSignedAccrualEvent({ domain: this.who.id, ...fields, previous: this.head }, this.who.secretKeyBytes, this.who.publicKeyBytes)); }
  evidence({ afterEpoch = 0, events = this.events, witnesses = [] } = {}) {
    return { version: 1, domain: this.who.id, afterEpoch, events: events.filter((e) => e.type !== 'progression' || e.payload.epoch > afterEpoch), witnesses };
  }
}
const submit = (who, evidence, extra = {}) => assessSubmission({ rewardParams: params, evidence, domain: who.id, ...extra });
const burnOf = (who, lamports = 3e9) => solana({ sig1: { payer: who.address, lamports } });

test('the domain of a Solana address is the hash of its key', async () => {
  const a = await person();
  assert.equal(await domainOfAddress(a.address), a.id);
});

test('a first submission: the figure comes out of the events, the burn is confirmed by the reader, the baseline is handed back', async () => {
  const a = await person();
  const h = new History(a);
  await h.burn('sig1'); await h.work(2); await h.commit({ b: 1 }); await h.work(6);
  const r = await submit(a, h.evidence(), { connection: burnOf(a) });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.mining.epoch, 8);
  assert.equal(r.ranking.laps, 6);
  assert.equal(r.baseline.epoch, 8);
  assert.equal(r.baseline.head, h.head);
});

test('no evidence, evidence for another domain, a burn Solana does not know: nothing is claimed', async () => {
  const a = await person(); const other = await person();
  const h = new History(a);
  await h.burn('sig1'); await h.work(2); await h.commit({ b: 1 }); await h.work(4);
  assert.match((await submit(a, null)).reason, /No evidence/);
  assert.match((await submit(other, h.evidence(), { connection: burnOf(a) })).reason, /not for this domain/);
  const unknown = await submit(a, h.evidence(), { connection: solana({}) });
  assert.equal(unknown.ok, true);
  assert.equal(unknown.mining, null, 'a valid history with no confirmed burn has no position');
  const notMine = await submit(a, h.evidence(), { connection: solana({ sig1: { payer: other.address, lamports: 3e9 } }) });
  assert.equal(notMine.mining, null, "somebody else's burn quoted by this domain does not count");
  await assert.rejects(submit(a, h.evidence()), /connection/, 'the reader must be able to ask Solana');
});

test('a second submission continues from the baseline: only the new events, chained, burns already counted not asked again', async () => {
  const a = await person();
  const h = new History(a);
  await h.burn('sig1'); await h.work(2); await h.commit({ b: 1 }); await h.work(3);
  const connection = burnOf(a);
  const first = await submit(a, h.evidence(), { connection });
  await h.work(4);
  const asked = connection.asked.length;
  const second = await submit(a, h.evidence({ afterEpoch: first.baseline.epoch, events: h.events.slice(-1) }), { connection, baseline: first.baseline });
  assert.equal(second.ok, true, second.reason);
  assert.equal(second.mining.epoch, 9);
  assert.equal(second.mining.claimable, (await submit(a, h.evidence(), { connection })).mining.claimable, 'the same figure as replaying everything');
  // the burn record travels again with the burn-records, but the baseline counted it: Solana is not asked
  const again = await submit(a, h.evidence({ afterEpoch: first.baseline.epoch, events: [h.events.find((e) => e.type === 'burn-record'), h.events.at(-1)] }), { connection, baseline: first.baseline });
  assert.equal(again.ok, true, again.reason);
  assert.equal(connection.asked.length, asked + 1 /* the full replay above, once */, 'no question for a burn the baseline already counted');

  const stale = await submit(a, h.evidence({ afterEpoch: 3, events: h.events.slice(-1) }), { connection, baseline: first.baseline });
  assert.match(stale.reason, /continues from epoch 3; this reader holds epoch 5/);
  assert.match((await submit(a, h.evidence({ afterEpoch: 5, events: h.events.slice(-1) }), { connection })).reason, /holds epoch none/);
});

test('a tampered event is set aside: the rest still counts, and the forged part does not', async () => {
  const a = await person();
  const h = new History(a);
  await h.burn('sig1'); await h.work(2); await h.commit({ b: 1 }); await h.work(5);
  const events = [...h.events];
  events[events.length - 1] = { ...events[events.length - 1], payload: { ...events[events.length - 1].payload, epoch: 999 } };
  const r = await submit(a, { ...h.evidence(), events }, { connection: burnOf(a) });
  assert.equal(r.mining.epoch, 2, 'the forged last epoch is not counted');
});

// --- witnesses ---------------------------------------------------------------------------------------------------

async function withHiddenAction(a) {
  const h = new History(a);
  await h.burn('sig1'); await h.work(2); await h.commit({ b: 1 }); await h.work(2);
  const small = await h.commit({ b: 0.2, T: 0.4 });
  const last = await h.work(2);
  return { h, small, last, witnessed: [{ id: last.id, epoch: last.payload.epoch }] };
}

test('witnesses: a history that contains what another holder has is accepted', async () => {
  const a = await person();
  const { h, witnessed } = await withHiddenAction(a);
  assert.equal((await submit(a, h.evidence(), { connection: burnOf(a), witnessed })).ok, true);
});

test('witnesses: an action left out is caught — the work after it does not stand without it, and the witness is missing', async () => {
  const a = await person();
  const { h, small, witnessed } = await withHiddenAction(a);
  const shown = h.events.filter((e) => e.id !== small.id);
  const alone = await submit(a, h.evidence({ events: shown }), { connection: burnOf(a) });
  assert.equal(alone.mining.epoch, 4, 'without a witness the history still stops at the action: the last epochs are bound to it');
  const caught = await submit(a, h.evidence({ events: shown }), { connection: burnOf(a), witnessed });
  assert.equal(caught.ok, false);
  assert.match(caught.reason, /Another holder of this domain's events/);
});

test('witnesses: a second history of the same key, valid on its own, is refused once someone holds the first', async () => {
  const a = await person();
  const { witnessed } = await withHiddenAction(a);
  const fork = new History(a);
  await fork.burn('sig1'); await fork.work(2); await fork.commit({ b: 1 }); await fork.work(4);
  assert.equal((await submit(a, fork.evidence(), { connection: burnOf(a) })).ok, true, 'valid by itself');
  const caught = await submit(a, fork.evidence(), { connection: burnOf(a), witnessed });
  assert.equal(caught.ok, false);
  assert.match(caught.reason, /does not contain it/);
});

test('witnesses: a history cut short is refused; a witness the baseline already passed is not asked for', async () => {
  const a = await person();
  const { h, witnessed } = await withHiddenAction(a);
  const connection = burnOf(a);
  assert.equal((await submit(a, h.evidence({ events: h.events.slice(0, -1) }), { connection, witnessed })).ok, false);
  const first = await submit(a, h.evidence(), { connection });
  await h.work(3);
  const next = await submit(a, h.evidence({ afterEpoch: first.baseline.epoch, events: h.events.slice(-1) }), { connection, baseline: first.baseline, witnessed });
  assert.equal(next.ok, true, next.reason);
});

test('ingestWitnesses keeps a real progression event of another domain, and ignores everything else', async () => {
  const a = await person(); const b = await person();
  const { h: mine } = await withHiddenAction(a);
  const { last } = await withHiddenAction(b);
  const forged = { ...last, payload: { ...last.payload, epoch: 99 } };
  const got = await ingestWitnesses({ ownDomain: a.id, witnesses: [last, last, forged, mine.events.find((e) => e.type === 'progression'), mine.events.find((e) => e.type === 'accrual'), null, 'x'] });
  assert.deepEqual(got.accepted, [{ domain: b.id, id: last.id, epoch: last.payload.epoch }], 'only the real one, once');
  assert.equal(got.ignored, 6, 'a copy, a forgery, my own, an accrual, and the garbage');
  const behind = await ingestWitnesses({ ownDomain: a.id, witnesses: [last], baselineEpochOf: () => last.payload.epoch });
  assert.deepEqual(behind.accepted, [], 'that epoch is already validated');
});

test('mergeWitnessStore keeps the furthest along per domain, bounded, and drops what has since been validated', () => {
  const d = 'd'.repeat(64);
  let store = mergeWitnessStore({}, Array.from({ length: 40 }, (_, i) => ({ domain: d, id: 'id' + i, epoch: i + 1 })));
  assert.equal(store[d].length, 32);
  assert.equal(store[d][0].epoch, 40, 'the furthest along first');
  assert.equal(store[d].at(-1).epoch, 9);
  store = mergeWitnessStore(store, [], () => 40);
  assert.deepEqual(store, {}, 'nothing is left to ask for once epoch 40 is validated');
});
