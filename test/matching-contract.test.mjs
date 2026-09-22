import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { buildGenerousSendCommitment, CONTRACT_ID as GENEROUS_CONTRACT_ID } from '../src/generous-transfer.js';
import { buildMatchCommitment, verifyMatchCommitmentSignature, verifyPayout, CONTRACT_ID } from '../src/matching-contract.js';

const VDF_ITERATIONS = 30;

function makeKeypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { secretKey: new Uint8Array([...seed, ...pubkeyBytes]), publicKey: { toBytes: () => pubkeyBytes } };
}
function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function canonicalTransferMessage({ claimId, from, to, nonce, timestamp }) {
  return JSON.stringify({ claimId, from, to, nonce, timestamp });
}
async function signRealTransfer(signer, { claimId, from, to }, nonce = 'real-nonce') {
  const timestamp = 1234567890;
  const message = new TextEncoder().encode(canonicalTransferMessage({ claimId, from, to, nonce, timestamp }));
  const signature = ed25519.sign(message, signer.secretKey.slice(0, 32));
  return { claimId, from, to, nonce, timestamp, signerPubkey: toHex(signer.publicKey.toBytes()), signature: toHex(signature) };
}

async function realWrappedProof({ donor, recipientDomain, thresholdBits, generousSendEventId }) {
  const commitment = await buildGenerousSendCommitment(donor, {
    baseTransferId: 't', to: recipientDomain, bonusClaimId: 'donor-claim', bonusAmount: '5', thresholdBits,
  });
  const seed = vdfSeed(recipientDomain, 'prior-real-output');
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  const qualifyingEpochEvent = { id: 'e6', parents: ['e5', generousSendEventId], payload: { type: 'progression', domain: recipientDomain, epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput } };
  return { commitment, generousSendEventId, qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' };
}

test('CONTRACT_ID is real, distinct from what it wraps', () => {
  assert.equal(CONTRACT_ID, 'aiwa-matching-v1');
  assert.notEqual(CONTRACT_ID, GENEROUS_CONTRACT_ID);
});

test('a real match commitment carries the real, correct wrapsContractId, verified against the real, imported constant', async () => {
  const matcher = makeKeypair();
  const commitment = await buildMatchCommitment(matcher, { wrappedGenerousSendEventId: 'gs-1', matchClaimId: 'c1', matchAmount: '3', to: 'bob' });
  assert.equal(commitment.wrapsContractId, GENEROUS_CONTRACT_ID);
  assert.equal(verifyMatchCommitmentSignature(commitment), true);
});

test('SECURITY: a match commitment claiming to wrap a different, fabricated contractId is rejected outright', async () => {
  const matcher = makeKeypair();
  const commitment = await buildMatchCommitment(matcher, { wrappedGenerousSendEventId: 'gs-1', matchClaimId: 'c1', matchAmount: '3', to: 'bob' });
  const tampered = { ...commitment, wrapsContractId: 'some-other-fabricated-contract-v1' };
  assert.equal(verifyMatchCommitmentSignature(tampered), false);
});

test('THE REAL, DIRECT COMPOSITION PROPERTY: a real win in the wrapped generous-transfer contract genuinely produces a valid matching payout', async () => {
  const matcher = makeKeypair();
  const donor = makeKeypair();
  const recipientDomain = 'bob-composed';

  const wrappedProof = await realWrappedProof({ donor, recipientDomain, thresholdBits: 0, generousSendEventId: 'gs-compose-1' });
  const matchCommitment = await buildMatchCommitment(matcher, {
    wrappedGenerousSendEventId: 'gs-compose-1', matchClaimId: 'matcher-claim', matchAmount: '3', to: recipientDomain,
  });
  const preSignedTransfer = await signRealTransfer(matcher, { claimId: 'matcher-claim', from: 'matcher-domain', to: recipientDomain });

  const payload = { ...preSignedTransfer, matchCommitment, wrappedProof };
  const result = await verifyPayout(payload);

  assert.ok(result, 'a real win in the wrapped contract must produce a real, valid composed payout');
  assert.equal(result.claimId, 'matcher-claim');
  assert.equal(result.to, recipientDomain);
});

test('SECURITY, THE REAL COMPOSED REJECTION: a real, honest LOSS in the wrapped contract is genuinely propagated — the composing contract never pays out on its own, disconnected from the real, underlying outcome', async () => {
  const matcher = makeKeypair();
  const donor = makeKeypair();
  const recipientDomain = 'bob-composed-loss';

  // thresholdBits: 256 — the real, underlying generous-transfer offer can never win.
  const wrappedProof = await realWrappedProof({ donor, recipientDomain, thresholdBits: 256, generousSendEventId: 'gs-compose-2' });
  const matchCommitment = await buildMatchCommitment(matcher, {
    wrappedGenerousSendEventId: 'gs-compose-2', matchClaimId: 'matcher-claim-2', matchAmount: '3', to: recipientDomain,
  });
  const preSignedTransfer = await signRealTransfer(matcher, { claimId: 'matcher-claim-2', from: 'matcher-domain', to: recipientDomain });

  const result = await verifyPayout({ ...preSignedTransfer, matchCommitment, wrappedProof });
  assert.equal(result, null, 'a real loss in the wrapped contract must genuinely propagate — the composing contract has no real basis to pay out');
});

test('SECURITY: a payload referencing a DIFFERENT wrapped offer id than the one actually resolved is rejected', async () => {
  const matcher = makeKeypair();
  const donor = makeKeypair();
  const recipientDomain = 'bob-composed-mismatch';

  const wrappedProof = await realWrappedProof({ donor, recipientDomain, thresholdBits: 0, generousSendEventId: 'gs-compose-real' });
  // Commitment claims to reference a DIFFERENT, unrelated offer id.
  const matchCommitment = await buildMatchCommitment(matcher, {
    wrappedGenerousSendEventId: 'gs-compose-DIFFERENT', matchClaimId: 'matcher-claim-3', matchAmount: '3', to: recipientDomain,
  });
  const preSignedTransfer = await signRealTransfer(matcher, { claimId: 'matcher-claim-3', from: 'matcher-domain', to: recipientDomain });

  const result = await verifyPayout({ ...preSignedTransfer, matchCommitment, wrappedProof });
  assert.equal(result, null, 'a real mismatch between the committed and the actually-supplied wrapped proof must be refused');
});

test('SECURITY: a real, tampered match commitment (amount altered after signing) is rejected even with a genuine underlying win', async () => {
  const matcher = makeKeypair();
  const donor = makeKeypair();
  const recipientDomain = 'bob-composed-tamper';

  const wrappedProof = await realWrappedProof({ donor, recipientDomain, thresholdBits: 0, generousSendEventId: 'gs-compose-3' });
  const matchCommitment = await buildMatchCommitment(matcher, {
    wrappedGenerousSendEventId: 'gs-compose-3', matchClaimId: 'matcher-claim-4', matchAmount: '3', to: recipientDomain,
  });
  const tamperedCommitment = { ...matchCommitment, matchAmount: '999999' };
  const preSignedTransfer = await signRealTransfer(matcher, { claimId: 'matcher-claim-4', from: 'matcher-domain', to: recipientDomain });

  const result = await verifyPayout({ ...preSignedTransfer, matchCommitment: tamperedCommitment, wrappedProof });
  assert.equal(result, null);
});

test('THE FULL, END-TO-END REAL COMPOSITION, THROUGH WALLET.JS\'S OWN GENERIC MECHANISM: a real matching payout, composed on top of a real generous-transfer win, actually moves real, spendable AIWA — both contracts registered, wallet.js\'s own source untouched', async () => {
  const { issueClaim } = await import('../src/conservation.js');
  const { initialWalletState, applyWalletEvent } = await import('../src/wallet.js');
  const { toUnits } = await import('../src/units.js');
  const { verifyPayout: verifyGenerousPayout } = await import('../src/generous-transfer.js');

  const REWARD_PARAMS = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };
  const CONTRACT_VERIFIERS = { [GENEROUS_CONTRACT_ID]: verifyGenerousPayout, [CONTRACT_ID]: verifyPayout };

  const matcher = makeKeypair();
  const recipientDomain = 'bob-full-e2e';
  const matcherDomainReal = toHex(await crypto.subtle.digest('SHA-256', matcher.publicKey.toBytes()).then((d) => new Uint8Array(d)));

  let wallet = initialWalletState();
  wallet = { ...wallet, conservation: issueClaim(wallet.conservation, { id: 'matcher-real-claim', kind: 'AIWA', amount: toUnits('3'), owner: matcherDomainReal }) };

  const donor = makeKeypair();
  const wrappedProof = await realWrappedProof({ donor, recipientDomain, thresholdBits: 0, generousSendEventId: 'gs-e2e-1' });
  const matchCommitment = await buildMatchCommitment(matcher, {
    wrappedGenerousSendEventId: 'gs-e2e-1', matchClaimId: 'matcher-real-claim', matchAmount: '3', to: recipientDomain,
  });
  const preSignedTransfer = await signRealTransfer(matcher, { claimId: 'matcher-real-claim', from: matcherDomainReal, to: recipientDomain });

  const payoutEvent = {
    id: 'real-composed-payout', parents: [],
    payload: { type: 'contract-payout', contractId: CONTRACT_ID, ...preSignedTransfer, matchCommitment, wrappedProof },
  };

  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, CONTRACT_VERIFIERS);

  assert.equal(wallet.rejections.length, 0, `expected no rejection, got: ${JSON.stringify(wallet.rejections)}`);
  const newClaims = Object.values(wallet.conservation.claims).filter((c) => c.status === 'active' && c.owner === recipientDomain);
  assert.equal(newClaims.length, 1, 'a real, new, active claim must genuinely belong to the real recipient, moved by real, direct composition between two real, independent contracts');
});
