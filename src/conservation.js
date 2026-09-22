// Deactivate -> Prove -> Verify -> Consume -> Activate. A transfer
// moves ownership without changing kind; a transmutation converts kind
// via an authorized derivation function (transfer is transmutation
// with the identity derivation). Load-bearing invariant:
// count(Consume(p)) <= 1, enforced by an idempotent consumed-proof set.
//
// Amounts are always real bigint smallest-units.

function assertBigInt(amount, label) {
  if (typeof amount !== 'bigint') throw new Error(`${label} must be a bigint, got ${typeof amount}`);
}

export function initialConservationState() {
  return { claims: {}, consumed: {} };
}

export function issueClaim(state, { id, kind, amount, owner }) {
  assertBigInt(amount, 'issueClaim amount');
  if (!(amount > 0n)) throw new Error(`amount must be positive, got ${amount}`);
  if (state.claims[id]) throw new Error(`Claim id already exists: ${id}`);
  return { ...state, claims: { ...state.claims, [id]: { id, kind, amount, owner, status: 'active' } } };
}

export function splitClaim(state, { claimId, firstAmount, firstId, secondId }) {
  assertBigInt(firstAmount, 'splitClaim firstAmount');
  const claim = state.claims[claimId];
  if (!claim) throw new Error(`Unknown claim: ${claimId}`);
  if (claim.status !== 'active') throw new Error(`Cannot split claim ${claimId}: status is '${claim.status}'`);
  if (!(firstAmount > 0n)) throw new Error(`firstAmount must be positive, got ${firstAmount}`);
  if (firstAmount >= claim.amount) throw new Error(`firstAmount must be strictly less than the claim's amount`);
  if (!firstId || !secondId || firstId === secondId) throw new Error('firstId and secondId must be distinct');
  if (state.claims[firstId] || state.claims[secondId]) throw new Error('firstId/secondId must be fresh ids');

  const secondAmount = claim.amount - firstAmount;
  const deactivated = deactivate(state, claimId);
  const withFirst = issueClaim(deactivated, { id: firstId, kind: claim.kind, amount: firstAmount, owner: claim.owner });
  return issueClaim(withFirst, { id: secondId, kind: claim.kind, amount: secondAmount, owner: claim.owner });
}

export function deactivate(state, claimId) {
  const claim = state.claims[claimId];
  if (!claim) throw new Error(`Unknown claim: ${claimId}`);
  if (claim.status !== 'active') throw new Error(`Cannot deactivate claim ${claimId}: status is '${claim.status}'`);
  return { ...state, claims: { ...state.claims, [claimId]: { ...claim, status: 'deactivated' } } };
}

function computeProofId({ claimId, from, to, n, derivation }) {
  return `${claimId}:${from}:${to}:${n}:${derivation}`;
}

export function proveTransfer(state, { claimId, from, to, n, derivation }, derivations) {
  const claim = state.claims[claimId];
  if (!claim) throw new Error(`Unknown claim: ${claimId}`);
  if (claim.status !== 'deactivated') throw new Error(`Cannot prove transfer for claim ${claimId}: status is '${claim.status}', not 'deactivated'`);
  if (claim.owner !== from) throw new Error(`Claim ${claimId} is not owned by ${from}`);
  const f = derivations[derivation];
  if (!f) throw new Error(`Unauthorized derivation: '${derivation}'`);
  const output = f(claim.kind, claim.amount);
  if (!output) throw new Error(`Derivation '${derivation}' rejected input`);
  assertBigInt(output.amount, `derivation '${derivation}' output amount`);
  return { id: computeProofId({ claimId, from, to, n, derivation }), claimId, from, to, derivation, kindOut: output.kind, amountOut: output.amount };
}

export function verify(state, proof, derivations) {
  const claim = state.claims[proof.claimId];
  if (!claim) return { valid: false, reason: `Unknown claim: ${proof.claimId}` };
  if (claim.status !== 'deactivated') return { valid: false, reason: `Claim ${proof.claimId} is not deactivated` };
  if (claim.owner !== proof.from) return { valid: false, reason: `Claim ${proof.claimId} is not owned by ${proof.from}` };
  if (state.consumed[proof.id]) return { valid: false, reason: `Proof ${proof.id} already consumed` };
  const f = derivations[proof.derivation];
  if (!f) return { valid: false, reason: `Unauthorized derivation: '${proof.derivation}'` };
  const expected = f(claim.kind, claim.amount);
  if (!expected || expected.kind !== proof.kindOut || expected.amount !== proof.amountOut) {
    return { valid: false, reason: 'Proof output does not match the derivation function' };
  }
  return { valid: true };
}

export function consume(state, proof) {
  if (state.consumed[proof.id]) throw new Error(`Replay rejected: proof ${proof.id} already consumed`);
  return { ...state, consumed: { ...state.consumed, [proof.id]: true } };
}

export function activate(state, proof) {
  if (!state.consumed[proof.id]) throw new Error(`Cannot activate: proof ${proof.id} not consumed`);
  const sourceClaim = state.claims[proof.claimId];
  if (!sourceClaim) throw new Error(`Unknown claim: ${proof.claimId}`);
  const destId = `activated:${proof.id}`;
  if (state.claims[destId]) throw new Error(`Activation already applied for proof ${proof.id}`);
  return {
    ...state,
    claims: {
      ...state.claims,
      [proof.claimId]: { ...sourceClaim, status: 'consumed' },
      [destId]: { id: destId, kind: proof.kindOut, amount: proof.amountOut, owner: proof.to, status: 'active' },
    },
  };
}

export function transfer(state, { claimId, from, to, n, derivation }, derivations) {
  let s = deactivate(state, claimId);
  const proof = proveTransfer(s, { claimId, from, to, n, derivation }, derivations);
  const check = verify(s, proof, derivations);
  if (!check.valid) throw new Error(`Verification failed: ${check.reason}`);
  s = consume(s, proof);
  s = activate(s, proof);
  return { state: s, proof };
}

export const identityDerivation = (kind, amount) => ({ kind, amount });
