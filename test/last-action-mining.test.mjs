import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { deriveId } from '../src/identity.js';
import { initialWalletState, applyWalletEvent, spendableClaims, totalBalance } from '../src/wallet.js';
import { buildSignedAccrualEvent, buildSignedClaimEvent, claimableNow, commitmentPriceLamports, withConfirmedBurns } from '../src/accrual.js';
import { buildSignedProgressionEvent } from '../src/progression.js';
import { serializeWalletState, deserializeWalletState } from '../src/checkpoint.js';
import { normalizeBurnTransaction } from '../src/burn-record.js';
import { SOLANA_INCINERATOR_ADDRESS } from '../src/identity-cost.js';
import { fromUnits } from '../src/units.js';

// "Last action" mining, as YourMine does it: a burn REPLACES the position, pays what the previous one accrued first,
// carries the T chosen at that burn, and T costs a share of the burn.
const free = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1, commitmentBacking: 'none' };
const enforced = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };

async function person() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkey = ed25519.getPublicKey(seed);
  return { seed, pubkey, domain: await deriveId(pubkey) };
}
let n = 0;
async function epochs(params, state, who, count) {
  for (let i = 0; i < count; i++) {
    const dom = state.accrual.progression.domains[who.domain] ?? { epoch: 0, vdfOutput: null, lastId: null };
    const epoch = dom.epoch + 1;
    const vdfOutput = await computeVdfChain(vdfSeed(who.domain, dom.vdfOutput ?? 'genesis'), 50);
    state = await applyWalletEvent(params, state, { id: `p${++n}`, parents: dom.lastId ? [dom.lastId] : [], payload: { type: 'progression', ...(await buildSignedProgressionEvent({ domain: who.domain, epoch, vdfIterations: 50, vdfOutput }, who.seed, who.pubkey)) } });
  }
  return state;
}
const commit = async (params, state, who, fields) =>
  applyWalletEvent(params, state, { id: `c${++n}`, parents: [], payload: { type: 'accrual', ...(await buildSignedAccrualEvent({ domain: who.domain, ...fields }, who.seed, who.pubkey)) } });
const position = (state, who) => state.accrual.positions[who.domain];
const reasons = (state) => state.accrual.rejections.map((r) => r.reason);

test('a second burn REPLACES the position: what mines is the last burn, and a small burn after a big one lowers it', async () => {
  const a = await person();
  let s = await epochs(free, initialWalletState(), a, 3);
  s = await commit(free, s, a, { b: 10 });
  s = await commit(free, s, a, { b: 0.001 });
  assert.equal(position(s, a).b, 0.001);
});

test('a second burn PAYS what the first accrued before replacing it — nothing is forfeited', async () => {
  const a = await person();
  let s = await epochs(free, initialWalletState(), a, 3);
  s = await commit(free, s, a, { b: 10 });
  s = await epochs(free, s, a, 8);
  const pending = claimableNow(free, s.accrual, a.domain);
  assert.ok(pending > 0n);
  assert.equal(spendableClaims(s, a.domain).length, 0);

  s = await commit(free, s, a, { b: 10 });
  assert.equal(claimableNow(free, s.accrual, a.domain), 0n, 'the clock restarted');
  const claims = spendableClaims(s, a.domain);
  assert.equal(claims.length, 1, 'the payment is a real claim, owned by the domain');
  assert.equal(claims[0].amount, pending, 'for exactly what was claimable at that moment');
  assert.match(claims[0].id, /^auto:/);
  assert.equal(s.accrual.balances[a.domain], pending);
  assert.equal(totalBalance(free, s, a.domain), pending);
});

test('a first burn has nothing to pay, and a burn with nothing accrued yet pays nothing', async () => {
  const a = await person();
  let s = await commit(free, initialWalletState(), a, { b: 5 });
  assert.equal(spendableClaims(s, a.domain).length, 0);
  s = await commit(free, s, a, { b: 5 }); // no epoch passed: q = 0, nothing accrued
  assert.equal(spendableClaims(s, a.domain).length, 0);
});

test('T is chosen at the burn for what follows: the next burn without a T goes back to 0, a claim keeps it', async () => {
  const a = await person();
  let s = await epochs(free, initialWalletState(), a, 3);
  s = await commit(free, s, a, { b: 10, T: 0.3 });
  assert.equal(position(s, a).T, 0.3);
  s = await epochs(free, s, a, 4);
  const amount = fromUnits(claimableNow(free, s.accrual, a.domain));
  s = await applyWalletEvent(free, s, { id: `k${++n}`, parents: [], payload: { type: 'claim', ...(await buildSignedClaimEvent({ domain: a.domain, claimId: `claim${n}`, amount }, a.seed, a.pubkey)) } });
  assert.equal(position(s, a).T, 0.3, 'a claim does not touch T: it costs nothing, so it cannot buy a better one');
  s = await commit(free, s, a, { b: 10 });
  assert.equal(position(s, a).T, 0, 'T is not inherited from the previous burn');
});

test('T must be between 0 and 0.4', async () => {
  const a = await person();
  for (const T of [-0.1, 0.41, 1, Number.NaN]) {
    const s = await commit(free, initialWalletState(), a, { b: 1, T });
    assert.equal(position(s, a), undefined, `T=${T} is refused`);
    assert.match(reasons(s)[0], /T must be between 0 and 0.4/);
  }
});

test('a higher T makes the same capital worth more, and the larger T is paid for out of the burn', async () => {
  const a = await person();
  const b = await person();
  let sa = await epochs(free, initialWalletState(), a, 3);
  let sb = await epochs(free, initialWalletState(), b, 3);
  sa = await commit(free, sa, a, { b: 10, T: 0 });
  sb = await commit(free, sb, b, { b: 10, T: 0.4 });
  sa = await epochs(free, sa, a, 6);
  sb = await epochs(free, sb, b, 6);
  assert.ok(claimableNow(free, sb.accrual, b.domain) > claimableNow(free, sa.accrual, a.domain), 'more generous curve');
  assert.equal(commitmentPriceLamports(10, 0), 10_000_000_000);
  assert.equal(commitmentPriceLamports(10, 0.4), Math.ceil(10_000_000_000 / 0.6));
});

// a Solana that says: this wallet burned `lamports` in transaction `signature`
const record = (who, lamports, signature) => normalizeBurnTransaction({
  slot: 1,
  transaction: { message: { accountKeys: [base58(who.pubkey), SOLANA_INCINERATOR_ADDRESS] } },
  meta: { err: null, fee: 5000, preBalances: [50e9, 0], postBalances: [50e9 - lamports - 5000, lamports] },
}, signature);
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let x = 0n;
  for (const v of bytes) x = x * 256n + BigInt(v);
  let out = '';
  while (x > 0n) { out = ALPHABET[Number(x % 58n)] + out; x /= 58n; }
  return out;
}
const burnEvent = (who, signature) => ({ id: `b${++n}`, parents: [], payload: { type: 'burn-record', domain: who.domain, signature } });

test('with the burn gate on, a commitment costs b / (1 - T) of confirmed burn, and each burn backs commitments only once', async () => {
  const a = await person();
  let s = withConfirmedBurns(initialWalletState(), { s1: record(a, 1_000_000_000, 's1') });
  s = await applyWalletEvent(enforced, s, burnEvent(a, 's1'));

  const tooMuch = await commit(enforced, s, a, { b: 0.61, T: 0.4 }); // would cost ceil(0.61 / 0.6) > 1 SOL
  assert.equal(position(tooMuch, a), undefined);
  assert.match(reasons(tooMuch)[0], /not covered by a confirmed burn/);

  s = await commit(enforced, s, a, { b: 0.6, T: 0.4 }); // costs the whole 1 SOL
  assert.equal(position(s, a).b, 0.6);
  assert.equal(s.accrual.burns.consumed[a.domain], 1_000_000_000);

  const again = await commit(enforced, s, a, { b: 0.1 });
  assert.equal(position(again, a).b, 0.6, 'the burn is spent: the position stays');
  assert.match(reasons(again).at(-1), /0 are left/);
});

test('a new burn lets the next commitment through, and the consumption survives a checkpoint', async () => {
  const a = await person();
  let s = withConfirmedBurns(initialWalletState(), { s1: record(a, 1_000_000_000, 's1'), s2: record(a, 2_000_000_000, 's2') });
  s = await applyWalletEvent(enforced, s, burnEvent(a, 's1'));
  s = await commit(enforced, s, a, { b: 1 });
  const revived = deserializeWalletState(serializeWalletState(s));
  assert.equal(revived.accrual.burns.consumed[a.domain], 1_000_000_000);
  s = await applyWalletEvent(enforced, revived, burnEvent(a, 's2'));
  s = await commit(enforced, s, a, { b: 2 });
  assert.equal(position(s, a).b, 2);
  assert.equal(s.accrual.burns.consumed[a.domain], 3_000_000_000);
});
