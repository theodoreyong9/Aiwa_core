import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '../src/identity.js';
import { initialWalletState, applyWalletEvent } from '../src/wallet.js';
import { withConfirmedBurns, buildSignedAccrualEvent } from '../src/accrual.js';
import { SOLANA_INCINERATOR_ADDRESS, identityCostFromBurns } from '../src/identity-cost.js';
import { base58Decode, normalizeBurnTransaction, fetchBurnRecord, verifyBurnRecordFor } from '../src/burn-record.js';
import { serializeWalletState, deserializeWalletState } from '../src/checkpoint.js';

// The genesis commitment (yellow paper §8), enforced: a domain's committed capital b may not exceed what burns
// THE READER confirmed for it. Mandatory unless the deployment says rewardParams.commitmentBacking = 'none'.
const base = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = '';
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
  return out;
}

async function person() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkey = ed25519.getPublicKey(seed);
  return { seed, pubkey, domain: await deriveId(pubkey), address: base58Encode(pubkey) };
}
// what Solana's getTransaction says about a burn of `lamports` paid by `who`
const solanaSays = (who, lamports, { fee = 5000, spent = lamports + fee, slot = 100, err = null } = {}) => ({
  slot, transaction: { message: { accountKeys: [who.address, SOLANA_INCINERATOR_ADDRESS, '11111111111111111111111111111111'] } },
  meta: { err, fee, preBalances: [10_000_000_000, 0, 1], postBalances: [10_000_000_000 - spent, lamports, 1] },
});
const recordOf = (who, lamports, signature, options) => normalizeBurnTransaction(solanaSays(who, lamports, options), signature);

let n = 0;
const event = (payload) => ({ id: `ev${++n}`, parents: [], payload });
async function commit(who, b) {
  return event({ type: 'accrual', ...(await buildSignedAccrualEvent({ domain: who.domain, b }, who.seed, who.pubkey)) });
}
const burnEvent = (who, signature) => event({ type: 'burn-record', domain: who.domain, signature });
async function fold(params, records, events) {
  let state = withConfirmedBurns(initialWalletState(), records);
  for (const e of events) state = await applyWalletEvent(params, state, e);
  return state;
}
const reasons = (state) => state.accrual.rejections.map((r) => r.reason);

test('MANDATORY by default: a commitment with no burn behind it is rejected, and creates nothing', async () => {
  const alice = await person();
  const state = await fold(base, {}, [await commit(alice, 100)]);
  assert.equal(state.accrual.positions[alice.domain], undefined);
  assert.match(reasons(state)[0], /not covered by a confirmed burn/);
});

test("an explicit commitmentBacking: 'none' restores the unbacked behaviour (tests, demos, private economies)", async () => {
  const alice = await person();
  const state = await fold({ ...base, commitmentBacking: 'none' }, {}, [await commit(alice, 100)]);
  assert.equal(state.accrual.positions[alice.domain].b, 100);
});

test('a confirmed burn covers a commitment up to what it burned — and not beyond', async () => {
  const alice = await person();
  const record = recordOf(alice, 2_000_000_000, 'sig-1'); // 2 units
  const records = { 'sig-1': record };
  const ok = await fold(base, records, [burnEvent(alice, 'sig-1'), await commit(alice, 2)]);
  assert.equal(ok.accrual.positions[alice.domain].b, 2);
  assert.equal(ok.accrual.burns.covered[alice.domain], 2_000_000_000);

  const over = await fold(base, records, [burnEvent(alice, 'sig-1'), await commit(alice, 3)]);
  assert.equal(over.accrual.positions[alice.domain], undefined);
  assert.match(reasons(over)[0], /not covered/);

  // cumulative: 1.5 fits, then a further 1 does not (2.5 > 2)
  const steps = await fold(base, records, [burnEvent(alice, 'sig-1'), await commit(alice, 1.5), await commit(alice, 1)]);
  assert.equal(steps.accrual.positions[alice.domain].b, 1.5);
  assert.equal(reasons(steps).length, 1);
});

test('two burns add up', async () => {
  const alice = await person();
  const records = { a: recordOf(alice, 1_000_000_000, 'a'), b: recordOf(alice, 1_000_000_000, 'b') };
  const state = await fold(base, records, [burnEvent(alice, 'a'), burnEvent(alice, 'b'), await commit(alice, 2)]);
  assert.equal(state.accrual.positions[alice.domain].b, 2);
});

test('a burn this reader has not confirmed counts for nothing — until it is confirmed and the log is folded again', async () => {
  const alice = await person();
  const events = [burnEvent(alice, 'sig-1'), await commit(alice, 1)];
  const before = await fold(base, {}, events);
  assert.equal(before.accrual.positions[alice.domain], undefined);
  assert.match(reasons(before)[0], /not confirmed by this reader/);
  const after = await fold(base, { 'sig-1': recordOf(alice, 1_000_000_000, 'sig-1') }, events);
  assert.equal(after.accrual.positions[alice.domain].b, 1);
});

test("someone else's burn cannot be claimed by quoting its signature", async () => {
  const alice = await person();
  const mallory = await person();
  const records = { 'alices-burn': recordOf(alice, 5_000_000_000, 'alices-burn') };
  const state = await fold(base, records, [burnEvent(mallory, 'alices-burn'), await commit(mallory, 1)]);
  assert.equal(state.accrual.burns.covered[mallory.domain], undefined);
  assert.match(reasons(state)[0], /not paid by this domain's own key/);
  assert.equal(state.accrual.positions[mallory.domain], undefined);
});

test('a burn where the key only paid the fee (someone else moved the money) does not bind', async () => {
  const alice = await person();
  const record = recordOf(alice, 1_000_000_000, 'sig-fee-only', { spent: 5000 });
  assert.equal((await verifyBurnRecordFor(alice.domain, record)).valid, false);
  assert.match((await verifyBurnRecordFor(alice.domain, record)).reason, /balance did not go down/);
});

test('one signature counts once, for one domain', async () => {
  const alice = await person();
  const records = { s: recordOf(alice, 1_000_000_000, 's') };
  const state = await fold(base, records, [burnEvent(alice, 's'), burnEvent(alice, 's'), await commit(alice, 2)]);
  assert.equal(state.accrual.burns.covered[alice.domain], 1_000_000_000);
  assert.ok(reasons(state).some((r) => /already counted/.test(r)));
  assert.equal(state.accrual.positions[alice.domain], undefined, 'and 2 units are not covered by 1');
});

test('the event says nothing about what the burn was worth: the reader\'s own record does', async () => {
  const alice = await person();
  const forged = event({ type: 'burn-record', domain: alice.domain, signature: 'sig', burnedLamports: 1e15 });
  const state = await fold(base, { sig: recordOf(alice, 1_000_000_000, 'sig') }, [forged, await commit(alice, 5)]);
  assert.equal(state.accrual.burns.covered[alice.domain], 1_000_000_000);
  assert.equal(state.accrual.positions[alice.domain], undefined);
});

test('a failed transaction is not a burn', async () => {
  const alice = await person();
  const record = recordOf(alice, 1_000_000_000, 'sig-err', { err: { InstructionError: [0, 'Custom'] } });
  assert.equal((await verifyBurnRecordFor(alice.domain, record)).valid, false);
});

test('fetchBurnRecord asks for the FINALIZED transaction, and an unknown one proves nothing', async () => {
  const alice = await person();
  const asked = [];
  const connection = { getTransaction: async (signature, options) => { asked.push([signature, options]); return signature === 'known' ? solanaSays(alice, 3_000_000_000) : null; } };
  const record = await fetchBurnRecord(connection, 'known');
  assert.deepEqual(asked[0], ['known', { commitment: 'finalized', maxSupportedTransactionVersion: 0 }]);
  assert.equal(record.incineratorBalanceDeltaLamports, 3_000_000_000);
  assert.equal(record.payerPubkey, Array.from(alice.pubkey).map((b) => b.toString(16).padStart(2, '0')).join(''));
  assert.equal(await fetchBurnRecord(connection, 'unknown'), null);
});

test('it reads a versioned transaction (static keys + loaded addresses) and keys given as objects', async () => {
  const alice = await person();
  const asObject = (text) => ({ toBase58: () => text });
  const rpc = {
    slot: 7,
    transaction: { message: { staticAccountKeys: [asObject(alice.address)] } },
    meta: { err: null, preBalances: [9_000_000_000, 0], postBalances: [8_000_000_000 - 5000, 1_000_000_000], loadedAddresses: { writable: [asObject(SOLANA_INCINERATOR_ADDRESS)], readonly: [] } },
  };
  const record = normalizeBurnTransaction(rpc, 'v0');
  assert.equal(record.incineratorBalanceDeltaLamports, 1_000_000_000);
  assert.equal((await verifyBurnRecordFor(alice.domain, record)).valid, true);
});

test('base58Decode round-trips a real key', async () => {
  const alice = await person();
  assert.deepEqual(base58Decode(alice.address), alice.pubkey);
});

test('the certified witness weight is what this reader confirmed, and the state survives a checkpoint round trip', async () => {
  const alice = await person();
  const state = await fold(base, { s: recordOf(alice, 4_000_000_000, 's') }, [burnEvent(alice, 's'), await commit(alice, 4)]);
  assert.equal(identityCostFromBurns(state.accrual.burns).registered[alice.domain].burnedLamports, 4_000_000_000);
  const revived = deserializeWalletState(serializeWalletState(state));
  assert.equal(revived.accrual.burns.covered[alice.domain], 4_000_000_000);
  assert.equal(revived.accrual.positions[alice.domain].b, 4);
});
