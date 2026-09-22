import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { issueClaim } from '../src/conservation.js';
import { initialWalletState, applyWalletEvent } from '../src/wallet.js';
import { buildGenerousSendCommitment, verifyPayout, CONTRACT_ID } from '../src/generous-transfer.js';
import { toUnits } from '../src/units.js';
import { deriveId } from '@aiwa/record';

const REWARD_PARAMS = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };
const VDF_ITERATIONS = 30;
const CONTRACT_VERIFIERS = { [CONTRACT_ID]: verifyPayout };

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function makeKeypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { secretKey: new Uint8Array([...seed, ...pubkeyBytes]), publicKey: { toBytes: () => pubkeyBytes } };
}
function canonicalTransferMessage({ claimId, from, to, nonce, timestamp }) {
  return JSON.stringify({ claimId, from, to, nonce, timestamp });
}
async function signRealTransfer(donor, { claimId, from, to }) {
  const nonce = 'real-nonce-1', timestamp = 1234567890;
  const message = new TextEncoder().encode(canonicalTransferMessage({ claimId, from, to, nonce, timestamp }));
  const signature = ed25519.sign(message, donor.secretKey.slice(0, 32));
  return { claimId, from, to, nonce, timestamp, signerPubkey: toHex(donor.publicKey.toBytes()), signature: toHex(signature) };
}

function withFundedClaim(walletState, { claimId, owner, amount }) {
  const conservation = issueClaim(walletState.conservation, { id: claimId, kind: 'AIWA', amount, owner });
  return { ...walletState, conservation };
}

test('THE FULL, END-TO-END REAL PAYOUT, THROUGH THE GENERIC MECHANISM: a real win, with a real signature, real VDF, and real Conservation, actually moves real, spendable AIWA', async () => {
  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());
  const recipientDomain = 'bob-real-domain';
  const bonusAmount = toUnits('5');

  let wallet = initialWalletState();
  wallet = withFundedClaim(wallet, { claimId: 'donor-bonus-claim', owner: donorDomain, amount: bonusAmount });

  const commitment = await buildGenerousSendCommitment(donor, {
    baseTransferId: 'real-base-transfer-1', to: recipientDomain, bonusClaimId: 'donor-bonus-claim', bonusAmount: '5', thresholdBits: 0,
  });

  const seed = vdfSeed(recipientDomain, 'prior-real-output');
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  const generousSendEventId = 'real-generous-send-event-id';
  const qualifyingEpochEvent = { id: 'bob-epoch-6', parents: ['bob-epoch-5', generousSendEventId], payload: { type: 'progression', domain: recipientDomain, epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput } };
  const preSignedTransfer = await signRealTransfer(donor, { claimId: 'donor-bonus-claim', from: donorDomain, to: recipientDomain });

  const payoutEvent = {
    id: 'real-payout-event', parents: [],
    payload: { type: 'contract-payout', contractId: CONTRACT_ID, ...preSignedTransfer, commitment, generousSendEventId, qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' },
  };

  const before = wallet.conservation.claims['donor-bonus-claim'];
  assert.equal(before.owner, donorDomain);
  assert.equal(before.status, 'active');

  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, CONTRACT_VERIFIERS);

  assert.equal(wallet.rejections.length, 0, `expected no rejection, got: ${JSON.stringify(wallet.rejections)}`);
  const originalClaim = wallet.conservation.claims['donor-bonus-claim'];
  assert.equal(originalClaim.status, 'consumed', 'the real, original claim must be consumed, never reused');
  const newClaims = Object.values(wallet.conservation.claims).filter((c) => c.status === 'active' && c.owner === recipientDomain);
  assert.equal(newClaims.length, 1, 'exactly one real, new, active claim must now genuinely belong to the real recipient');
  assert.equal(newClaims[0].amount, bonusAmount, 'the real, full bonus amount must have genuinely moved');
});

test('SECURITY: a payout referencing an unregistered contractId is rejected outright', async () => {
  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());
  const recipientDomain = 'bob-unreg';
  let wallet = initialWalletState();
  wallet = withFundedClaim(wallet, { claimId: 'c1', owner: donorDomain, amount: toUnits('5') });
  const preSignedTransfer = await signRealTransfer(donor, { claimId: 'c1', from: donorDomain, to: recipientDomain });

  const payoutEvent = { id: 'p-unreg', parents: [], payload: { type: 'contract-payout', contractId: 'some-unregistered-contract-v1', ...preSignedTransfer } };
  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, CONTRACT_VERIFIERS);

  assert.equal(wallet.rejections.length, 1);
  assert.match(wallet.rejections[0].reason, /unregistered contract/);
  assert.equal(wallet.conservation.claims['c1'].owner, donorDomain);
});

test('SECURITY: with an EMPTY registry, an otherwise-valid real payout is still refused — nothing is trusted by default', async () => {
  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());
  const recipientDomain = 'bob-empty-registry';
  let wallet = initialWalletState();
  wallet = withFundedClaim(wallet, { claimId: 'c1', owner: donorDomain, amount: toUnits('5') });
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't', to: recipientDomain, bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 0 });
  const seed = vdfSeed(recipientDomain, 'prior');
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  const qualifyingEpochEvent = { id: 'e6', parents: ['e5', 'gs-1'], payload: { type: 'progression', domain: recipientDomain, epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput } };
  const preSignedTransfer = await signRealTransfer(donor, { claimId: 'c1', from: donorDomain, to: recipientDomain });

  const payoutEvent = { id: 'p-empty', parents: [], payload: { type: 'contract-payout', contractId: CONTRACT_ID, ...preSignedTransfer, commitment, generousSendEventId: 'gs-1', qualifyingEpochEvent, priorVdfOutput: 'prior' } };
  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, {});

  assert.equal(wallet.rejections.length, 1);
  assert.match(wallet.rejections[0].reason, /unregistered contract/);
});

test('SECURITY: a real, honest LOSS is rejected by the contract\'s own verifier, never silently paid out', async () => {
  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());
  const recipientDomain = 'bob-real-domain-3';
  let wallet = initialWalletState();
  wallet = withFundedClaim(wallet, { claimId: 'c3', owner: donorDomain, amount: toUnits('5') });

  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't', to: recipientDomain, bonusClaimId: 'c3', bonusAmount: '5', thresholdBits: 256 });
  const seed = vdfSeed(recipientDomain, 'prior-real-output');
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  const qualifyingEpochEvent = { id: 'e6', parents: ['e5', 'gs-3'], payload: { type: 'progression', domain: recipientDomain, epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput } };
  const preSignedTransfer = await signRealTransfer(donor, { claimId: 'c3', from: donorDomain, to: recipientDomain });

  const payoutEvent = { id: 'p3', parents: [], payload: { type: 'contract-payout', contractId: CONTRACT_ID, ...preSignedTransfer, commitment, generousSendEventId: 'gs-3', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' } };
  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, CONTRACT_VERIFIERS);

  assert.equal(wallet.rejections.length, 1);
  assert.match(wallet.rejections[0].reason, /rejected its own real conditions/);
  assert.equal(wallet.conservation.claims['c3'].owner, donorDomain);
});

test('SECURITY: a payout whose pre-signed transfer does not match what the contract commitment actually authorized is rejected', async () => {
  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());
  const recipientDomain = 'bob-real-domain-4';
  let wallet = initialWalletState();
  wallet = withFundedClaim(wallet, { claimId: 'real-claim-A', owner: donorDomain, amount: toUnits('5') });
  wallet = withFundedClaim(wallet, { claimId: 'real-claim-B', owner: donorDomain, amount: toUnits('100') });

  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't', to: recipientDomain, bonusClaimId: 'real-claim-A', bonusAmount: '5', thresholdBits: 0 });
  const seed = vdfSeed(recipientDomain, 'prior-real-output');
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  const qualifyingEpochEvent = { id: 'e6', parents: ['e5', 'gs-4'], payload: { type: 'progression', domain: recipientDomain, epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput } };
  const preSignedTransfer = await signRealTransfer(donor, { claimId: 'real-claim-B', from: donorDomain, to: recipientDomain });

  const payoutEvent = { id: 'p4', parents: [], payload: { type: 'contract-payout', contractId: CONTRACT_ID, ...preSignedTransfer, commitment, generousSendEventId: 'gs-4', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' } };
  wallet = await applyWalletEvent(REWARD_PARAMS, wallet, payoutEvent, null, CONTRACT_VERIFIERS);

  assert.equal(wallet.rejections.length, 1);
  assert.match(wallet.rejections[0].reason, /rejected its own real conditions/);
  assert.equal(wallet.conservation.claims['real-claim-B'].owner, donorDomain, 'the larger, real claim must never move on a mismatched commitment');
});
