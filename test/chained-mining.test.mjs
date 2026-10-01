import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity } from '../src/identity.js';
import { createEvent } from '../src/event.js';
import { computeSuccinctEpochs } from '../src/succinct-vdf.js';
import { buildSignedProgressionEvent, progressionSeed } from '../src/progression.js';
import { buildSignedAccrualEvent, buildSignedClaimEvent } from '../src/accrual.js';
import { assessMining } from '../src/mining-state.js';

// The mining events of a domain are a line, and the line is signed: each one names the one it follows (`previous`),
// and the work of an epoch starts from it. So an action cannot be left out of a history, nor a history re-signed over
// another, without redoing the work that follows it.
const EI = 100;
const params = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1, epochIterations: EI, commitmentBacking: 'none' };

async function person() {
  const who = await generateIdentity();
  who.secretKeyBytes = Uint8Array.from(Buffer.from(who.secretKey ?? who._secretKey ?? '', 'hex'));
  who.publicKeyBytes = Uint8Array.from(Buffer.from(who.publicKey, 'hex'));
  return who;
}

// A domain's own history, event by event, as a wallet builds it.
function wallet(who) {
  const events = [];
  const w = { events, head: null, output: null, epoch: 0, parents: [] };
  const push = async (type, payload, previousForParents = w.parents) => {
    const e = await createEvent(who, { domain: `log:${who.id}`, parents: previousForParents, type, payload });
    events.push(e);
    w.parents = [e.id];
    return e;
  };
  w.work = async (epochs = 1, { previous = w.head, output = w.output } = {}) => {
    const iterations = epochs * EI;
    const work = await computeSuccinctEpochs(progressionSeed(who.id, output, previous), iterations);
    const signed = await buildSignedProgressionEvent({ domain: who.id, epoch: w.epoch + epochs, vdfIterations: iterations, vdfOutput: work.vdfOutput, previous }, who.secretKeyBytes, who.publicKeyBytes);
    const e = await push('progression', { ...signed, vdfProof: work.vdfProof });
    w.head = e.id; w.output = work.vdfOutput; w.epoch += epochs;
    return e;
  };
  w.commit = async (fields, { previous = w.head } = {}) => {
    const signed = await buildSignedAccrualEvent({ domain: who.id, ...fields, previous }, who.secretKeyBytes, who.publicKeyBytes);
    const e = await push('accrual', signed);
    w.head = e.id;
    return e;
  };
  w.claim = async (claimId, amount, { previous = w.head } = {}) => {
    const signed = await buildSignedClaimEvent({ domain: who.id, claimId, amount, previous }, who.secretKeyBytes, who.publicKeyBytes);
    const e = await push('claim', signed);
    w.head = e.id;
    return e;
  };
  return w;
}
const assess = (who, events, baseline) => assessMining({ rewardParams: params, events, domain: who.id, baseline });

test('an honest line is accepted whole: work, action, work, action', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(2);
  await w.commit({ b: 6, T: 0.1 });
  await w.work(3);
  const r = await assess(a, w.events);
  assert.deepEqual(r.rejections, []);
  assert.equal(r.mining.epoch, 5);
  assert.equal(r.mining.capital, 6);
  assert.equal(r.mining.chainHead, w.head);
});

test('an action left out of the history cuts everything after it: the work that follows is bound to it', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(2);
  const x = await w.commit({ b: 1, T: 0.4 }); // the action to hide (a small burn that would restart the clock)
  await w.work(3);
  const shown = w.events.filter((e) => e.id !== x.id);
  const r = await assess(a, shown);
  assert.equal(r.mining.epoch, 2, 'the three epochs worked after the hidden action do not count without it');
  assert.equal(r.mining.capital, 4);
  assert.ok(r.rejections.some((rej) => /last mining event/.test(rej.reason)));
});

test('the same proven work re-signed over a history without the action is refused: the work starts from the action', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(2);
  const beforeAction = w.head;
  const outputBefore = w.output;
  const x = await w.commit({ b: 1, T: 0.4 });
  const after = await w.work(3);
  // the cheat: take the real proof of the epochs after X, name the earlier event as the predecessor, sign it again
  const forged = await buildSignedProgressionEvent(
    { domain: a.id, epoch: after.payload.epoch, vdfIterations: after.payload.vdfIterations, vdfOutput: after.payload.vdfOutput, previous: beforeAction },
    a.secretKeyBytes, a.publicKeyBytes,
  );
  const reSigned = await createEvent(a, { domain: `log:${a.id}`, parents: [beforeAction], type: 'progression', payload: { ...forged, vdfProof: after.payload.vdfProof } });
  const shown = [...w.events.filter((e) => e.id !== x.id && e.id !== after.id), reSigned];
  const r = await assess(a, shown);
  assert.equal(r.mining.epoch, 2);
  assert.ok(r.rejections.some((rej) => /does not verify/.test(rej.reason)), JSON.stringify(r.rejections));
  assert.ok(outputBefore);
});

test('two actions that follow the same event: only one counts — a reader is never asked to pick the favourable one', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(1);
  const head = w.head;
  const big = await w.commit({ b: 9 }, { previous: head });
  const small = await w.commit({ b: 1 }, { previous: head }); // a second history from the same point
  const first = await assess(a, [...w.events.filter((e) => e.id !== small.id)]);
  const second = await assess(a, [...w.events.filter((e) => e.id !== big.id)]);
  assert.equal(first.mining.capital, 9);
  assert.equal(second.mining.capital, 1);
  // shown together, the one folded first stays and the other is refused
  const both = await assess(a, w.events);
  assert.equal(both.rejections.filter((rej) => /last mining event/.test(rej.reason)).length, 1);
});

test('an action cannot be placed earlier than it was made: it must follow the last mining event, not an older one', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  const old = w.head;
  await w.work(5);
  await w.claim('c1', '0.000001'); // a real claim, after five epochs
  const backdated = await w.commit({ b: 4 }, { previous: old }); // pretends to have followed the first accrual
  const r = await assess(a, w.events);
  assert.ok(r.rejections.some((rej) => rej.eventId === backdated.id && /last mining event/.test(rej.reason)));
});

test('an event that does not name what it follows is refused in a work-bound deployment', async () => {
  const a = await person();
  const w = wallet(a);
  const signed = await buildSignedAccrualEvent({ domain: a.id, b: 4 }, a.secretKeyBytes, a.publicKeyBytes); // no `previous`
  await createEvent(a, { domain: `log:${a.id}`, parents: [], type: 'accrual', payload: signed }).then((e) => w.events.push(e));
  const r = await assess(a, w.events);
  assert.equal(r.mining, null);
  assert.match(r.rejections[0].reason, /must name the mining event it follows/);
});

test('a validator that kept a baseline continues from its chain head — and refuses a continuation of another history', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(2);
  const first = await assess(a, w.events);
  const checkpoint = w.events.length;
  await w.work(2);
  await w.commit({ b: 2 });
  await w.work(1);
  const next = await assess(a, w.events.slice(checkpoint), first.state);
  assert.deepEqual(next.rejections, []);
  assert.equal(next.mining.epoch, 5);
  // a history that forked at the baseline's head continues from somewhere else: refused
  const fork = wallet(a);
  fork.head = 'not-the-head';
  fork.epoch = 2; fork.output = first.state.accrual.progression.domains[a.id].vdfOutput;
  await fork.work(2);
  const forked = await assess(a, fork.events, first.state);
  assert.equal(forked.mining.epoch, 2);
  assert.ok(forked.rejections.some((rej) => /last mining event/.test(rej.reason)));
});

test('the chain does not depend on the events\' parents: a checkpoint (or anything else) in between changes nothing', async () => {
  const a = await person();
  const w = wallet(a);
  await w.commit({ b: 4 });
  await w.work(2);
  // something else becomes the head of the log: the next event's parents do not name the last progression
  w.parents = ['a-checkpoint-or-a-reception'];
  await w.work(2);
  const r = await assess(a, w.events);
  assert.deepEqual(r.rejections, []);
  assert.equal(r.mining.epoch, 4);
});
