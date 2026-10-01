import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { vdfSeed, computeVdfChain } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import { computeSuccinctEpochs, verifySuccinctEpochs } from '../src/succinct-vdf.js';
import { RSA_2048_MODULUS } from '../src/wesolowski-vdf.js';
import { buildSignedProgressionEvent, applyProgressionEvent, initialProgressionState } from '../src/progression.js';
import { replayProgression } from '../src/triangulation.js';

// A deployment that fixes the work of one epoch: epochIterations. Small here so the tests are quick; a real one is
// large (the wallet page uses 300 000).
const EI = 200;
const opts = { epochIterations: EI };

async function person() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkey = ed25519.getPublicKey(seed);
  return { seed, pubkey, domain: await deriveId(pubkey) };
}
let n = 0;
// a progression event of `epochs` epochs after `state`'s current one, with the work done honestly (or as told)
async function event(who, state, { epochs = 1, iterations = epochs * EI, tamper } = {}) {
  const current = state.domains[who.domain] ?? { epoch: 0, vdfOutput: null, lastId: null };
  const seed = vdfSeed(who.domain, current.vdfOutput ?? 'genesis');
  let work = await computeSuccinctEpochs(seed, iterations);
  if (tamper) work = tamper(work);
  const signed = await buildSignedProgressionEvent({ domain: who.domain, epoch: current.epoch + epochs, vdfIterations: iterations, vdfOutput: work.vdfOutput }, who.seed, who.pubkey);
  return { id: `e${++n}`, parents: current.lastId ? [current.lastId] : [], payload: { type: 'progression', ...signed, vdfProof: work.vdfProof } };
}
const accepted = (before, after) => after.rejections.length === before.rejections.length;

test('an epoch of the fixed work, with its proof, is accepted — and so is a chain of them', async () => {
  const a = await person();
  let s = initialProgressionState();
  for (let i = 0; i < 3; i++) {
    const before = s;
    s = await applyProgressionEvent(s, await event(a, s), null, opts);
    assert.ok(accepted(before, s), JSON.stringify(s.rejections));
  }
  assert.equal(s.domains[a.domain].epoch, 3);
});

test('k epochs in ONE event: k x epochIterations squarings, one proof, the epoch count jumps by k', async () => {
  const a = await person();
  let s = initialProgressionState();
  s = await applyProgressionEvent(s, await event(a, s, { epochs: 1 }), null, opts);
  const before = s;
  s = await applyProgressionEvent(s, await event(a, s, { epochs: 5 }), null, opts);
  assert.ok(accepted(before, s), JSON.stringify(s.rejections));
  assert.equal(s.domains[a.domain].epoch, 6);
});

test('the old shortcut is closed: an "epoch" with fewer iterations than the deployment fixes is refused', async () => {
  const a = await person();
  const s = initialProgressionState();
  const cheap = await event(a, s, { epochs: 1, iterations: 1 });
  const after = await applyProgressionEvent(s, cheap, null, opts);
  assert.equal(after.domains[a.domain], undefined);
  assert.match(after.rejections[0].reason, /an epoch is 200/);
});

test('claiming more epochs than the work done is refused, however the numbers are written', async () => {
  const a = await person();
  const s = initialProgressionState();
  // 10 epochs announced, the work of 1 done and proven honestly
  const work = await computeSuccinctEpochs(vdfSeed(a.domain, 'genesis'), EI);
  const signed = await buildSignedProgressionEvent({ domain: a.domain, epoch: 10, vdfIterations: EI, vdfOutput: work.vdfOutput }, a.seed, a.pubkey);
  const lie = { id: 'lie', parents: [], payload: { type: 'progression', ...signed, vdfProof: work.vdfProof } };
  const after = await applyProgressionEvent(s, lie, null, opts);
  assert.equal(after.domains[a.domain], undefined);
  // and the same with the iterations raised to match: the proof is for 200 squarings, not 2000
  const signed2 = await buildSignedProgressionEvent({ domain: a.domain, epoch: 10, vdfIterations: 10 * EI, vdfOutput: work.vdfOutput }, a.seed, a.pubkey);
  const lie2 = { id: 'lie2', parents: [], payload: { type: 'progression', ...signed2, vdfProof: work.vdfProof } };
  const after2 = await applyProgressionEvent(s, lie2, null, opts);
  assert.equal(after2.domains[a.domain], undefined);
  assert.match(after2.rejections[0].reason, /does not verify/);
});

test('a hash-chain output is not accepted by a deployment that fixes the work of an epoch', async () => {
  const a = await person();
  const s = initialProgressionState();
  const seed = vdfSeed(a.domain, 'genesis');
  const vdfOutput = await computeVdfChain(seed, EI);
  const signed = await buildSignedProgressionEvent({ domain: a.domain, epoch: 1, vdfIterations: EI, vdfOutput }, a.seed, a.pubkey);
  const after = await applyProgressionEvent(s, { id: 'h', parents: [], payload: { type: 'progression', ...signed } }, null, opts);
  assert.equal(after.domains[a.domain], undefined);
});

test('a tampered output or proof, a non-canonical output (y + N) and another domain\'s work are all refused', async () => {
  const a = await person();
  const b = await person();
  const s = initialProgressionState();
  const flip = (hex) => (hex[0] === '1' ? '2' : '1') + hex.slice(1);
  const cases = {
    'tampered output': (w) => ({ ...w, vdfOutput: flip(w.vdfOutput) }),
    'tampered proof': (w) => ({ ...w, vdfProof: { ...w.vdfProof, pi: flip(w.vdfProof.pi) } }),
    'y + N': (w) => ({ ...w, vdfOutput: (BigInt('0x' + w.vdfOutput) + RSA_2048_MODULUS).toString(16) }),
    'leading zero': (w) => ({ ...w, vdfOutput: '0' + w.vdfOutput }),
    'no proof': (w) => ({ ...w, vdfProof: undefined }),
  };
  for (const [name, tamper] of Object.entries(cases)) {
    const after = await applyProgressionEvent(s, await event(a, s, { tamper }), null, opts);
    assert.equal(after.domains[a.domain], undefined, name);
  }
  // b's work, signed by a under a's domain: the work starts from b's seed, not a's
  const bWork = await computeSuccinctEpochs(vdfSeed(b.domain, 'genesis'), EI);
  const signed = await buildSignedProgressionEvent({ domain: a.domain, epoch: 1, vdfIterations: EI, vdfOutput: bWork.vdfOutput }, a.seed, a.pubkey);
  const borrowed = await applyProgressionEvent(s, { id: 'x', parents: [], payload: { type: 'progression', ...signed, vdfProof: bWork.vdfProof } }, null, opts);
  assert.equal(borrowed.domains[a.domain], undefined, 'work cannot be borrowed');
});

test('the work of an epoch cannot be done ahead: it starts from the previous output', async () => {
  const a = await person();
  let s = initialProgressionState();
  const first = await event(a, s);
  const aheadSeed = vdfSeed(a.domain, first.payload.vdfOutput);
  assert.equal(await verifySuccinctEpochs(vdfSeed(a.domain, 'genesis'), EI, first.payload.vdfOutput, first.payload.vdfProof), true);
  assert.equal(await verifySuccinctEpochs(aheadSeed, EI, first.payload.vdfOutput, first.payload.vdfProof), false);
});

test('verifying is far cheaper than producing — a validator does not redo the work', async () => {
  const seed = vdfSeed('d'.repeat(64), 'genesis');
  const iterations = 150_000;
  let t = performance.now();
  const work = await computeSuccinctEpochs(seed, iterations);
  const produce = performance.now() - t;
  t = performance.now();
  assert.equal(await verifySuccinctEpochs(seed, iterations, work.vdfOutput, work.vdfProof), true);
  const verify = performance.now() - t;
  assert.ok(verify * 20 < produce, `produce ${Math.round(produce)} ms, verify ${Math.round(verify)} ms`);
});

test('replayProgression reads a chain that starts with a k-epoch event as starting at the genesis', async () => {
  const a = await person();
  let s = initialProgressionState();
  const e1 = await event(a, s, { epochs: 3 });
  s = await applyProgressionEvent(s, e1, null, opts);
  const e2 = await event(a, s, { epochs: 1 });
  const replay = await replayProgression([e1, e2], a.domain, null, opts);
  assert.equal(replay.genesis, true);
  assert.equal(replay.accepted.size, 2);
  const late = await replayProgression([e2], a.domain, null, opts);
  assert.equal(late.genesis, false, 'a reader who holds only a later event does not read it as a forged genesis');
  assert.equal(late.accepted.size, 0);
});
