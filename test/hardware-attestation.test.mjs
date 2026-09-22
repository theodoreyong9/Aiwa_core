import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveId } from '@aiwa/record';
import {
  issueHardwareRoot, bindHardwareRoot, verifyHardwareAttestation, isIndependenceAttested, MIN_INDEPENDENT_ROOTS,
} from '../src/hardware-attestation.js';

function makeSigner() {
  const seed = ed25519.utils.randomSecretKey();
  const pubkeyBytes = ed25519.getPublicKey(seed);
  return { seed, pubkeyBytes };
}
function makeKeypair() {
  const s = makeSigner();
  return { secretKey: new Uint8Array([...s.seed, ...s.pubkeyBytes]), publicKey: { toBytes: () => s.pubkeyBytes } };
}

async function realAttestation(originKeypair, originDomain, targetDomain) {
  const root = makeSigner();
  const issuance = await issueHardwareRoot(originKeypair, originDomain, root.pubkeyBytes);
  const binding = await bindHardwareRoot(root.seed, root.pubkeyBytes, targetDomain);
  return { issuance, binding };
}

test('MIN_INDEPENDENT_ROOTS is the real, documented minimum of two', () => {
  assert.equal(MIN_INDEPENDENT_ROOTS, 2);
});

test('a real, complete attestation verifies', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const attestation = await realAttestation(origin, originDomain, 'target-domain');
  assert.equal(await verifyHardwareAttestation(attestation, 'target-domain'), true);
});

test('SECURITY: an attestation bound to a different domain than claimed is rejected', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const attestation = await realAttestation(origin, originDomain, 'real-domain');
  assert.equal(await verifyHardwareAttestation(attestation, 'different-domain'), false);
});

test('SECURITY: a forged issuance (wrong origin signature) is rejected', async () => {
  const realOrigin = makeKeypair();
  const attacker = makeKeypair();
  const realOriginDomain = await deriveId(realOrigin.publicKey.toBytes());
  const root = makeSigner();
  const forgedIssuance = await issueHardwareRoot(attacker, realOriginDomain, root.pubkeyBytes);
  const binding = await bindHardwareRoot(root.seed, root.pubkeyBytes, 'target-domain');
  assert.equal(await verifyHardwareAttestation({ issuance: forgedIssuance, binding }, 'target-domain'), false);
});

test('SECURITY: a forged binding (wrong hardware root signature) is rejected', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const root = makeSigner();
  const attacker = makeSigner();
  const issuance = await issueHardwareRoot(origin, originDomain, root.pubkeyBytes);
  const forgedBinding = await bindHardwareRoot(attacker.seed, root.pubkeyBytes, 'target-domain');
  assert.equal(await verifyHardwareAttestation({ issuance, binding: forgedBinding }, 'target-domain'), false);
});

test('SECURITY: THE REAL BOUNDARY — a single, real, fully valid attestation is NOT enough', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const one = await realAttestation(origin, originDomain, 'target-domain');
  assert.equal(await isIndependenceAttested([one], 'target-domain'), false, 'one real root must never pass the gate — the whole point of requiring two');
});

test('two real, distinct, fully valid attestations DO pass the gate', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const a = await realAttestation(origin, originDomain, 'target-domain');
  const b = await realAttestation(origin, originDomain, 'target-domain');
  assert.equal(await isIndependenceAttested([a, b], 'target-domain'), true);
});

test('SECURITY: the same physical hardware root re-attested twice still counts once, not two distinct roots', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const root = makeSigner();
  const issuance = await issueHardwareRoot(origin, originDomain, root.pubkeyBytes);
  const bindingA = await bindHardwareRoot(root.seed, root.pubkeyBytes, 'target-domain', { boundAt: 1 });
  const bindingB = await bindHardwareRoot(root.seed, root.pubkeyBytes, 'target-domain', { boundAt: 2 });
  const result = await isIndependenceAttested([{ issuance, binding: bindingA }, { issuance, binding: bindingB }], 'target-domain');
  assert.equal(result, false, 'the same hardware root counted twice must never satisfy a real minimum of two DISTINCT roots');
});

test('malformed or missing attestations are rejected without throwing', async () => {
  assert.equal(await verifyHardwareAttestation(null, 'target-domain'), false);
  assert.equal(await verifyHardwareAttestation({}, 'target-domain'), false);
  assert.equal(await verifyHardwareAttestation({ issuance: {}, binding: {} }, 'target-domain'), false);
  assert.equal(await isIndependenceAttested([], 'target-domain'), false);
  assert.equal(await isIndependenceAttested(null, 'target-domain'), false);
});

test('SECURITY: mismatched hardware root pubkeys between issuance and binding are rejected', async () => {
  const origin = makeKeypair();
  const originDomain = await deriveId(origin.publicKey.toBytes());
  const rootA = makeSigner();
  const rootB = makeSigner();
  const issuance = await issueHardwareRoot(origin, originDomain, rootA.pubkeyBytes);
  const binding = await bindHardwareRoot(rootB.seed, rootB.pubkeyBytes, 'target-domain');
  assert.equal(await verifyHardwareAttestation({ issuance, binding }, 'target-domain'), false);
});
