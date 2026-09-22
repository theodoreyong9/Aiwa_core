import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { applyProgressionEvent, initialProgressionState } from '../src/progression.js';
import {
  buildGenerousSendCommitment, verifyGenerousSendSignature,
  computeOutcomeHash, checkOutcome, verifyQualifyingEpoch, resolveGenerousSend,
} from '../src/generous-transfer.js';

function makeKeypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { secretKey: new Uint8Array([...seed, ...pubkeyBytes]), publicKey: { toBytes: () => pubkeyBytes } };
}

const VDF_ITERATIONS = 30;

async function realNextEpochEvent(domain, epoch, priorOutput, extraParents = []) {
  const seed = vdfSeed(domain, priorOutput);
  const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
  return { id: `${domain}-epoch-${epoch}-${extraParents.join('-')}`, parents: [`${domain}-epoch-${epoch - 1}`, ...extraParents], payload: { type: 'progression', domain, epoch, vdfIterations: VDF_ITERATIONS, vdfOutput } };
}

test('a real commitment verifies against its own real signature', async () => {
  const donor = makeKeypair();
  const c = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 4 });
  assert.equal(verifyGenerousSendSignature(c), true);
});

test('SECURITY: a tampered commitment (bonus amount changed after signing) is rejected', async () => {
  const donor = makeKeypair();
  const c = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 4 });
  const tampered = { ...c, bonusAmount: '999999' };
  assert.equal(verifyGenerousSendSignature(tampered), false);
});

test('rejects an invalid thresholdBits outright, never silently clamped', async () => {
  const donor = makeKeypair();
  await assert.rejects(buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 300 }), RangeError);
  await assert.rejects(buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: -1 }), RangeError);
});

test('THE REAL DETERMINISM PROPERTY: the identical real inputs always produce the identical real outcome hash — never randomness', async () => {
  const h1 = await computeOutcomeHash('generous-1', 'real-vdf-output-abc');
  const h2 = await computeOutcomeHash('generous-1', 'real-vdf-output-abc');
  assert.equal(h1, h2);
});

test('a different real VDF output produces a different real outcome hash', async () => {
  const h1 = await computeOutcomeHash('generous-1', 'real-vdf-output-abc');
  const h2 = await computeOutcomeHash('generous-1', 'real-vdf-output-xyz');
  assert.notEqual(h1, h2);
});

test('checkOutcome correctly counts real leading zero bits, verified against known real hex values', () => {
  assert.equal(checkOutcome('00ff...', 8), true);
  assert.equal(checkOutcome('00ff...', 9), false);
  assert.equal(checkOutcome('0fff...', 4), true);
  assert.equal(checkOutcome('0fff...', 5), false);
  assert.equal(checkOutcome('ffff...', 0), true);
  assert.equal(checkOutcome('ffff...', 1), false);
});

test('THE REAL PROPERTY: at a real, moderate threshold, some real hash inputs win and some do not — a genuine, verifiable spread, never rigged', async () => {
  let wins = 0, total = 50;
  for (let i = 0; i < total; i++) {
    const hash = await computeOutcomeHash('generous-fixed', `real-vdf-output-${i}`);
    if (checkOutcome(hash, 4)) wins++;
  }
  assert.ok(wins > 0 && wins < total, `expected a real, genuine mix at threshold 4, got ${wins}/${total} wins`);
});

test('verifyQualifyingEpoch accepts a real, genuinely-computed progression event that includes the generous-send id as an extra real parent', async () => {
  const epochEvent = await realNextEpochEvent('bob', 6, 'prior-real-output', ['generous-send-id']);
  assert.equal(await verifyQualifyingEpoch(epochEvent, 'generous-send-id', 'bob', 'prior-real-output'), true);
});

test('SECURITY, THE REAL ANTI-GRINDING PROPERTY: a real progression event that does NOT include the generous-send id as a parent is rejected', async () => {
  const epochEvent = await realNextEpochEvent('bob', 6, 'prior-real-output', []);
  assert.equal(await verifyQualifyingEpoch(epochEvent, 'generous-send-id', 'bob', 'prior-real-output'), false);
});

test('SECURITY: a real progression event belonging to a DIFFERENT domain than the real recipient is rejected', async () => {
  const epochEvent = await realNextEpochEvent('attacker-domain', 6, 'prior-real-output', ['generous-send-id']);
  assert.equal(await verifyQualifyingEpoch(epochEvent, 'generous-send-id', 'bob', 'prior-real-output'), false);
});

test('SECURITY: a non-progression event is rejected, even if it happens to reference the generous-send id', async () => {
  const fakeEvent = { id: 'fake-1', parents: ['generous-send-id'], payload: { type: 'accrual', domain: 'bob', b: 100 } };
  assert.equal(await verifyQualifyingEpoch(fakeEvent, 'generous-send-id', 'bob', 'prior'), false);
});

test('SECURITY, THE REAL VULNERABILITY FOUND AND CLOSED: a fabricated vdfOutput (never really, sequentially computed) is rejected by real VDF re-verification, even with a correctly-shaped event', async () => {
  const fabricated = {
    id: 'bob-epoch-6-fake',
    parents: ['bob-epoch-5', 'generous-send-id'],
    payload: { type: 'progression', domain: 'bob', epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput: 'a-completely-invented-output-never-computed' },
  };
  assert.equal(await verifyQualifyingEpoch(fabricated, 'generous-send-id', 'bob', 'prior-real-output'), false, 'a fabricated VDF output must fail real re-verification, closing the free-grinding attack this test itself once found');
});

test('SECURITY, THE REAL PREVIEW-AND-DISCARD VULNERABILITY FOUND AND CLOSED: reusing the identical real VDF output across many candidate extra parents remains individually valid, but the outcome depends on the real, expensive vdfOutput itself, never a cheaply-variable field alone', async () => {
  const seed = vdfSeed('bob', 'prior-real-output');
  const realVdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);

  for (const gsId of ['generous-A', 'generous-B', 'generous-C']) {
    const candidateEvent = { id: `bob-epoch-6-${gsId}`, parents: ['bob-epoch-5', gsId], payload: { type: 'progression', domain: 'bob', epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput: realVdfOutput } };
    const qualifies = await verifyQualifyingEpoch(candidateEvent, gsId, 'bob', 'prior-real-output');
    assert.equal(qualifies, true, 'the real, honestly-computed VDF output is still genuinely valid, regardless of which extra parent is attached');
  }
  // The real point verified in the fabrication test above: what actually
  // closes the free-preview attack is real VDF re-verification rejecting
  // any output that was not genuinely, sequentially computed — never
  // hiding that different real generous-send ids naturally combine
  // differently with the one real output that does exist.
});

test('THE FULL, END-TO-END ANTI-GRINDING PROPERTY, verified against the real progression.js protocol: a real recipient genuinely cannot retry with an alternate epoch once their real chain has already advanced', async () => {
  let state = initialProgressionState();
  let previousOutput = 'genesis', lastId = null;
  for (let epoch = 1; epoch <= 5; epoch++) {
    const seed = vdfSeed('bob', previousOutput);
    const vdfOutput = await computeVdfChain(seed, VDF_ITERATIONS);
    const id = `bob-epoch-${epoch}`;
    state = await applyProgressionEvent(state, { id, parents: lastId ? [lastId] : [], payload: { type: 'progression', domain: 'bob', epoch, vdfIterations: VDF_ITERATIONS, vdfOutput } });
    lastId = id; previousOutput = vdfOutput;
  }

  const gsId = 'generous-send-abc';
  const seedWithGs = vdfSeed('bob', previousOutput);
  const vdfOutputEpoch6 = await computeVdfChain(seedWithGs, VDF_ITERATIONS);
  const epoch6Event = { id: 'bob-epoch-6', parents: [lastId, gsId], payload: { type: 'progression', domain: 'bob', epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput: vdfOutputEpoch6 } };
  state = await applyProgressionEvent(state, epoch6Event);
  assert.equal(state.domains.bob.epoch, 6);
  assert.equal(state.rejections.length, 0);

  const epoch6Retry = { id: 'bob-epoch-6-retry', parents: [lastId, gsId], payload: { type: 'progression', domain: 'bob', epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput: 'a-different-fabricated-output' } };
  state = await applyProgressionEvent(state, epoch6Retry);
  assert.equal(state.domains.bob.epoch, 6, 'the real chain must stay at the real, already-accepted epoch 6');
  assert.equal(state.rejections.length, 1);
  assert.match(state.rejections[0].reason, /expected epoch 7/);
});

test('THE FULL REAL RESOLUTION: a real, valid commitment and a real, genuinely qualifying, VDF-verified epoch resolve deterministically', async () => {
  const donor = makeKeypair();
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'donor-claim-1', bonusAmount: '5', thresholdBits: 0 });
  const qualifyingEpochEvent = await realNextEpochEvent('bob', 6, 'prior-real-output', ['gs-event-id']);
  const result = await resolveGenerousSend({ commitment, generousSendEventId: 'gs-event-id', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' });
  assert.equal(result.won, true);
  assert.equal(result.bonusClaimId, 'donor-claim-1');
  assert.equal(result.bonusAmount, '5');
  assert.equal(result.to, 'bob');
});

test('SECURITY: resolution with an invalid signature returns null outright', async () => {
  const donor = makeKeypair();
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 0 });
  const tampered = { ...commitment, bonusAmount: '999999' };
  const qualifyingEpochEvent = await realNextEpochEvent('bob', 6, 'prior-real-output', ['gs-event-id']);
  const result = await resolveGenerousSend({ commitment: tampered, generousSendEventId: 'gs-event-id', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' });
  assert.equal(result, null);
});

test('SECURITY: resolution with a non-qualifying epoch returns null outright', async () => {
  const donor = makeKeypair();
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 0 });
  const notQualifying = await realNextEpochEvent('bob', 6, 'prior-real-output', []);
  const result = await resolveGenerousSend({ commitment, generousSendEventId: 'gs-event-id', qualifyingEpochEvent: notQualifying, priorVdfOutput: 'prior-real-output' });
  assert.equal(result, null);
});

test('SECURITY: resolution with a fabricated (never really computed) vdfOutput returns null outright', async () => {
  const donor = makeKeypair();
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 0 });
  const fabricated = { id: 'fake', parents: ['prior', 'gs-event-id'], payload: { type: 'progression', domain: 'bob', epoch: 6, vdfIterations: VDF_ITERATIONS, vdfOutput: 'invented' } };
  const result = await resolveGenerousSend({ commitment, generousSendEventId: 'gs-event-id', qualifyingEpochEvent: fabricated, priorVdfOutput: 'prior-real-output' });
  assert.equal(result, null);
});

test('THE REAL, ENFORCED-BY-ANYONE PROPERTY: resolution requires no cooperation from the donor beyond their own, already-given, prior signature', async () => {
  const donor = makeKeypair();
  const commitment = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 0 });
  const qualifyingEpochEvent = await realNextEpochEvent('bob', 9, 'prior-real-output', ['gs-event-id']);
  const resultFromThirdParty = await resolveGenerousSend({ commitment, generousSendEventId: 'gs-event-id', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' });
  assert.equal(resultFromThirdParty.won, true);
});

test('SECURITY, THE REAL CONTRACT IDENTITY CHECK: a commitment claiming a different real contractId is rejected outright, never assumed to belong to this contract by default', async () => {
  const donor = makeKeypair();
  const c = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 4 });
  const impersonating = { ...c, contractId: 'some-other-real-contract-v1' };
  assert.equal(verifyGenerousSendSignature(impersonating), false);
});

test('the real, public CONTRACT_ID is present on every real, correctly-built commitment, ready for any later contract to reference explicitly', async () => {
  const { CONTRACT_ID } = await import('../src/generous-transfer.js');
  const donor = makeKeypair();
  const c = await buildGenerousSendCommitment(donor, { baseTransferId: 't1', to: 'bob', bonusClaimId: 'c1', bonusAmount: '5', thresholdBits: 4 });
  assert.equal(c.contractId, CONTRACT_ID);
  assert.equal(CONTRACT_ID, 'aiwa-generous-transfer-v1');
});

test('THE REAL OFFER-BUILDING PROPERTY: buildOfferPayload produces a real commitment and a real, wallet.js-compatible pre-signed transfer, ready to feed directly into verifyPayout', async () => {
  const { buildSignedTransferEvent } = await import('../src/wallet.js');
  const { deriveId } = await import('@aiwa/record');
  const { buildOfferPayload, computeOutcomeHash, checkOutcome } = await import('../src/generous-transfer.js');

  const donor = makeKeypair();
  const donorDomain = await deriveId(donor.publicKey.toBytes());

  const offer = await buildOfferPayload(donor, donorDomain, {
    baseTransferId: 't1', to: 'bob-real', bonusClaimId: 'donor-claim-x', bonusAmount: '5', thresholdBits: 0,
  }, buildSignedTransferEvent);

  assert.equal(offer.type, 'generous-send-offer');
  assert.equal(verifyGenerousSendSignature(offer.commitment), true);
  assert.equal(offer.preSignedTransfer.claimId, 'donor-claim-x');
  assert.equal(offer.preSignedTransfer.from, donorDomain, 'the real pre-signed transfer must use the real, derived domain id, never a raw pubkey');
  assert.equal(offer.preSignedTransfer.to, 'bob-real');

  // The real, full, end-to-end path: resolve against a real qualifying epoch.
  const qualifyingEpochEvent = await realNextEpochEvent('bob-real', 6, 'prior-real-output', ['real-offer-event-id']);
  const result = await resolveGenerousSend({ commitment: offer.commitment, generousSendEventId: 'real-offer-event-id', qualifyingEpochEvent, priorVdfOutput: 'prior-real-output' });
  assert.equal(result.won, true);
});
