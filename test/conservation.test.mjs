import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  initialConservationState, issueClaim, deactivate, proveTransfer, verify, consume, activate,
  transfer, identityDerivation, splitClaim,
} from '../src/conservation.js';

const derivations = { identity: identityDerivation };

test('a plain transfer moves ownership without changing kind or amount', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  const { state: after, proof } = transfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations);
  assert.equal(after.claims.c1.status, 'consumed');
  const dest = after.claims[`activated:${proof.id}`];
  assert.equal(dest.amount, 10n);
  assert.equal(dest.owner, 'bob');
  assert.equal(dest.status, 'active');
});

test('a transmutation converts kind via an authorized derivation function', () => {
  const burnXMintY = (kind, amount) => (kind === 'X' ? { kind: 'Y', amount: amount * 2n } : null);
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  const { state: after, proof } = transfer(state, { claimId: 'c1', from: 'alice', to: 'alice', n: 'n1', derivation: 'burnXMintY' }, { identity: identityDerivation, burnXMintY });
  const minted = after.claims[`activated:${proof.id}`];
  assert.equal(minted.kind, 'Y');
  assert.equal(minted.amount, 20n);
});

test('an unauthorized derivation is rejected at Prove', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  state = deactivate(state, 'c1');
  assert.throws(() => proveTransfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'nope' }, derivations), /Unauthorized/);
});

test('protocol order enforced: cannot Prove before Deactivate', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  assert.throws(() => proveTransfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations), /deactivated/);
});

test('protocol order enforced: cannot Activate before Consume', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  state = deactivate(state, 'c1');
  const proof = proveTransfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations);
  assert.throws(() => activate(state, proof), /not consumed/);
});

test('count(Consume(p)) <= 1: consuming the same proof twice is rejected', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  state = deactivate(state, 'c1');
  const proof = proveTransfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations);
  const after = consume(state, proof);
  assert.throws(() => consume(after, proof), /already consumed/);
});

test('verify rejects a proof whose claimed output does not match the derivation', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'X', amount: 10n, owner: 'alice' });
  state = deactivate(state, 'c1');
  const proof = proveTransfer(state, { claimId: 'c1', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations);
  const forged = { ...proof, amountOut: 999n };
  assert.equal(verify(state, forged, derivations).valid, false);
});

test('issueClaim rejects a plain number amount', () => {
  assert.throws(() => issueClaim(initialConservationState(), { id: 'c1', kind: 'X', amount: 10, owner: 'alice' }), /bigint/);
});

test('splitClaim divides one claim into two summing exactly to the original', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'AIWA', amount: 10n, owner: 'alice' });
  state = splitClaim(state, { claimId: 'c1', firstAmount: 3n, firstId: 'c1a', secondId: 'c1b' });
  assert.equal(state.claims.c1.status, 'deactivated');
  assert.equal(state.claims.c1a.amount, 3n);
  assert.equal(state.claims.c1b.amount, 7n);
  assert.equal(state.claims.c1a.amount + state.claims.c1b.amount, 10n);
});

test('SECURITY: splitClaim rejects a firstAmount consuming the whole claim', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'AIWA', amount: 10n, owner: 'alice' });
  assert.throws(() => splitClaim(state, { claimId: 'c1', firstAmount: 10n, firstId: 'a', secondId: 'b' }), /strictly less than/);
});

test('SECURITY: splitClaim rejects a non-positive or non-bigint firstAmount', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'AIWA', amount: 10n, owner: 'alice' });
  assert.throws(() => splitClaim(state, { claimId: 'c1', firstAmount: 0n, firstId: 'a', secondId: 'b' }));
  assert.throws(() => splitClaim(state, { claimId: 'c1', firstAmount: 3, firstId: 'a', secondId: 'b' }), /bigint/);
});

test('SECURITY: splitClaim rejects reusing an existing claim id', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'AIWA', amount: 10n, owner: 'alice' });
  state = issueClaim(state, { id: 'existing', kind: 'AIWA', amount: 1n, owner: 'bob' });
  assert.throws(() => splitClaim(state, { claimId: 'c1', firstAmount: 3n, firstId: 'existing', secondId: 'b' }), /fresh/);
});

test('a split-off half is real, active, and independently transferable', () => {
  let state = initialConservationState();
  state = issueClaim(state, { id: 'c1', kind: 'AIWA', amount: 10n, owner: 'alice' });
  state = splitClaim(state, { claimId: 'c1', firstAmount: 3n, firstId: 'c1a', secondId: 'c1b' });
  state = deactivate(state, 'c1a');
  const proof = proveTransfer(state, { claimId: 'c1a', from: 'alice', to: 'bob', n: 'n1', derivation: 'identity' }, derivations);
  assert.equal(verify(state, proof, derivations).valid, true);
  state = consume(state, proof);
  state = activate(state, proof);
  assert.equal(state.claims[`activated:${proof.id}`].amount, 3n);
});
