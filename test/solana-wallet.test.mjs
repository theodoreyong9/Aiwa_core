import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as solanaWeb3 from '@solana/web3.js';
import {
  generateKeypair, keypairFromSecretKey, encryptSecretKey, decryptSecretKey,
  buildBurnTransaction, buildTransferTransaction, signAndSerialize, generateLightweightKeypair, lightweightKeypairFromSecretKey,
  deriveKeypairFromPassphrase, deriveKeypairFromBip39Mnemonic, validateBip39Mnemonic, toIdentity,
} from '../src/solana-wallet.js';
import { SOLANA_INCINERATOR_ADDRESS } from '../src/identity-cost.js';
import { deriveId } from '../src/identity.js';

test('generateKeypair produces a real, usable Ed25519 keypair', () => {
  const kp = generateKeypair(solanaWeb3);
  assert.ok(kp.publicKey instanceof solanaWeb3.PublicKey);
  assert.equal(kp.secretKey.length, 64);
});

test('keypairFromSecretKey reconstructs the identical keypair', () => {
  const original = generateKeypair(solanaWeb3);
  const rebuilt = keypairFromSecretKey(solanaWeb3, original.secretKey);
  assert.equal(rebuilt.publicKey.toBase58(), original.publicKey.toBase58());
});

test('encryptSecretKey / decryptSecretKey round-trips the real secret key bytes', async () => {
  const kp = generateKeypair(solanaWeb3);
  const record = await encryptSecretKey(kp.secretKey, 'a real password');
  const decrypted = await decryptSecretKey(record, 'a real password');
  assert.deepEqual(Array.from(decrypted), Array.from(kp.secretKey));
});

test('decryptSecretKey rejects the wrong password instead of returning garbage', async () => {
  const kp = generateKeypair(solanaWeb3);
  const record = await encryptSecretKey(kp.secretKey, 'right password');
  await assert.rejects(decryptSecretKey(record, 'wrong password'), /Wrong password/);
});

test('buildBurnTransaction targets the real incinerator address', () => {
  const kp = generateKeypair(solanaWeb3);
  const tx = buildBurnTransaction(solanaWeb3, { fromPubkey: kp.publicKey, lamports: 1000, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() });
  const instruction = tx.instructions[0];
  const toPubkey = new solanaWeb3.PublicKey(instruction.keys[1].pubkey);
  assert.equal(toPubkey.toBase58(), SOLANA_INCINERATOR_ADDRESS);
});

test('buildBurnTransaction rejects a non-positive lamport amount', () => {
  const kp = generateKeypair(solanaWeb3);
  assert.throws(() => buildBurnTransaction(solanaWeb3, { fromPubkey: kp.publicKey, lamports: 0, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() }), RangeError);
});

test('buildTransferTransaction targets the real, chosen recipient — never the incinerator', () => {
  const kp = generateKeypair(solanaWeb3);
  const recipient = generateKeypair(solanaWeb3);
  const tx = buildTransferTransaction(solanaWeb3, { fromPubkey: kp.publicKey, toAddress: recipient.publicKey.toBase58(), lamports: 1000, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() });
  const instruction = tx.instructions[0];
  const toPubkey = new solanaWeb3.PublicKey(instruction.keys[1].pubkey);
  assert.equal(toPubkey.toBase58(), recipient.publicKey.toBase58());
  assert.notEqual(toPubkey.toBase58(), SOLANA_INCINERATOR_ADDRESS);
});

test('buildTransferTransaction rejects a non-positive lamport amount', () => {
  const kp = generateKeypair(solanaWeb3);
  const recipient = generateKeypair(solanaWeb3);
  assert.throws(() => buildTransferTransaction(solanaWeb3, { fromPubkey: kp.publicKey, toAddress: recipient.publicKey.toBase58(), lamports: -1, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() }), RangeError);
});

test('SECURITY: buildTransferTransaction rejects a real, malformed, invalid Solana address rather than silently sending nowhere', () => {
  const kp = generateKeypair(solanaWeb3);
  assert.throws(() => buildTransferTransaction(solanaWeb3, { fromPubkey: kp.publicKey, toAddress: 'not-a-real-address', lamports: 1000, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() }), /valid Solana address/);
});

test('signAndSerialize produces real, validly-signed bytes', () => {
  const kp = generateKeypair(solanaWeb3);
  const tx = buildBurnTransaction(solanaWeb3, { fromPubkey: kp.publicKey, lamports: 1000, recentBlockhash: solanaWeb3.Keypair.generate().publicKey.toBase58() });
  const raw = signAndSerialize(tx, kp);
  const roundTripped = solanaWeb3.Transaction.from(raw);
  assert.equal(roundTripped.signatures[0].publicKey.toBase58(), kp.publicKey.toBase58());
});

test('generateLightweightKeypair produces a real, usable keypair shape, no @solana/web3.js involved', async () => {
  const kp = await generateLightweightKeypair();
  assert.equal(kp.secretKey.length, 64);
  assert.equal(kp.publicKey.toBytes().length, 32);
  assert.equal(typeof kp.publicKey.toBase58(), 'string');
});

test('THE REAL PROPERTY: a lightweight keypair and a real solanaWeb3 keypair from the identical seed derive the identical base58 address', async () => {
  const solanaKp = generateKeypair(solanaWeb3);
  const rebuilt = await lightweightKeypairFromSecretKey(solanaKp.secretKey);
  assert.equal(rebuilt.publicKey.toBase58(), solanaKp.publicKey.toBase58(), 'the lightweight path must derive the exact same real identity as the full library would');
});

test('lightweightKeypairFromSecretKey round-trips a real secret key exactly', async () => {
  const original = await generateLightweightKeypair();
  const rebuilt = await lightweightKeypairFromSecretKey(original.secretKey);
  assert.deepEqual(Array.from(rebuilt.secretKey), Array.from(original.secretKey));
  assert.equal(rebuilt.publicKey.toBase58(), original.publicKey.toBase58());
});

test('SECURITY: lightweightKeypairFromSecretKey rejects a secret key whose embedded public half does not match', async () => {
  const a = await generateLightweightKeypair();
  const b = await generateLightweightKeypair();
  const tampered = new Uint8Array(64);
  tampered.set(a.secretKey.slice(0, 32), 0);
  tampered.set(b.publicKey.toBytes(), 32);
  await assert.rejects(lightweightKeypairFromSecretKey(tampered), /does not match/);
});

test('lightweightKeypairFromSecretKey rejects the wrong length', async () => {
  await assert.rejects(lightweightKeypairFromSecretKey(new Uint8Array(32)), /64-byte/);
});

test('THE REAL PROPERTY: the same passphrase derives the identical real identity, every time', async () => {
  const a = await deriveKeypairFromPassphrase('correct horse battery staple');
  const b = await deriveKeypairFromPassphrase('correct horse battery staple');
  assert.equal(a.publicKey.toBase58(), b.publicKey.toBase58());
  assert.deepEqual(Array.from(a.secretKey), Array.from(b.secretKey));
});

test('a different passphrase derives a different, real identity', async () => {
  const a = await deriveKeypairFromPassphrase('passphrase one');
  const b = await deriveKeypairFromPassphrase('passphrase two');
  assert.notEqual(a.publicKey.toBase58(), b.publicKey.toBase58());
});

test('deriveKeypairFromPassphrase produces a real, usable keypair shape', async () => {
  const kp = await deriveKeypairFromPassphrase('a real test passphrase');
  assert.equal(kp.secretKey.length, 64);
  assert.equal(kp.publicKey.toBytes().length, 32);
  assert.equal(typeof kp.publicKey.toBase58(), 'string');
});

test('THE REAL STANDARD PROPERTY: a real BIP39 mnemonic derives the identical real address a standard Solana wallet (Phantom/Solflare) would show, at the real m/44\'/501\'/0\'/0\' path', async () => {
  // Real, independently-known test vectors — cross-checked against a
  // second, independent library (ed25519-hd-key) before ever being
  // trusted here. Never invented, never assumed.
  const vectors = [
    { mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', expected: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk' },
    { mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow', expected: 'BLeUXTx9thHGT7VJUtF9vHEmfMDgW1nnKZ9UVer2CoLX' },
    { mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong', expected: 'E48cosDiQZK1iDSsyUzhvW4WxJeoKuDk5qgcdkmANV4N' },
  ];
  for (const { mnemonic, expected } of vectors) {
    const kp = await deriveKeypairFromBip39Mnemonic(mnemonic);
    assert.equal(kp.publicKey.toBase58(), expected, `mnemonic starting '${mnemonic.slice(0, 15)}...' must derive the real, standard address`);
  }
});

test('deriveKeypairFromBip39Mnemonic is deterministic — the identical mnemonic always derives the identical real address', async () => {
  const mnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  const a = await deriveKeypairFromBip39Mnemonic(mnemonic);
  const b = await deriveKeypairFromBip39Mnemonic(mnemonic);
  assert.equal(a.publicKey.toBase58(), b.publicKey.toBase58());
});

test('a different, real, valid mnemonic derives a different, real address', async () => {
  const a = await deriveKeypairFromBip39Mnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const b = await deriveKeypairFromBip39Mnemonic('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
  assert.notEqual(a.publicKey.toBase58(), b.publicKey.toBase58());
});

test('a different real account index derives a different real address from the same real mnemonic', async () => {
  const mnemonic = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  const account0 = await deriveKeypairFromBip39Mnemonic(mnemonic, 0);
  const account1 = await deriveKeypairFromBip39Mnemonic(mnemonic, 1);
  assert.notEqual(account0.publicKey.toBase58(), account1.publicKey.toBase58());
});

test('SECURITY: an invalid mnemonic (bad checksum, wrong words) is rejected, never silently used', async () => {
  await assert.rejects(deriveKeypairFromBip39Mnemonic('not a real bip39 mnemonic at all here whatsoever'), /valid BIP39/);
});

test('validateBip39Mnemonic correctly distinguishes real, valid mnemonics from invalid ones', async () => {
  assert.equal(await validateBip39Mnemonic('legal winner thank year wave sausage worth useful legal winner thank yellow'), true);
  assert.equal(await validateBip39Mnemonic('not a real mnemonic'), false);
});

test('toIdentity bridges this module\'s keypair into a real identity.js Identity sharing the identical Ed25519 seed', async () => {
  const kp = await generateLightweightKeypair();
  const identity = await toIdentity(kp);
  assert.equal(identity.id, await deriveId(kp.publicKey.toBytes()));
  assert.equal(identity.publicKey, Array.from(kp.publicKey.toBytes()).map((b) => b.toString(16).padStart(2, '0')).join(''));
});

test('toIdentity can sign, and its signature verifies against the same identity', async () => {
  const kp = await generateLightweightKeypair();
  const identity = await toIdentity(kp);
  const message = new TextEncoder().encode('hello');
  const signature = await identity.sign(message);
  assert.equal(await identity.verify(message, signature), true);
});

test('generateBip39Mnemonic: a fresh valid phrase (12 words by default, 24 on request) that derives the same key every time', async () => {
  const { generateBip39Mnemonic, validateBip39Mnemonic, deriveKeypairFromBip39Mnemonic } = await import('../src/solana-wallet.js');
  const a = await generateBip39Mnemonic();
  const b = await generateBip39Mnemonic();
  assert.equal(a.split(' ').length, 12);
  assert.notEqual(a, b);
  assert.equal(await validateBip39Mnemonic(a), true);
  assert.equal((await generateBip39Mnemonic(24)).split(' ').length, 24);
  await assert.rejects(generateBip39Mnemonic(13), /12 or 24/);
  const k1 = await deriveKeypairFromBip39Mnemonic(a);
  const k2 = await deriveKeypairFromBip39Mnemonic(a);
  assert.equal(k1.publicKey.toBase58(), k2.publicKey.toBase58(), 'logging in with the phrase gives the same address');
  assert.notEqual((await deriveKeypairFromBip39Mnemonic(b)).publicKey.toBase58(), k1.publicKey.toBase58());
});

test('base58Encode is the inverse of base58Decode, keeps leading zero bytes, and writes a secret key the way Solana wallets do', async () => {
  const { base58Encode, base58Decode } = await import('../src/burn-record.js');
  assert.equal(base58Encode(new TextEncoder().encode('Hello World!')), '2NEpo7TZRRrLZSi2U', 'the reference vector');
  assert.deepEqual(base58Decode(base58Encode(Uint8Array.from([0, 0, 1, 2, 255]))), Uint8Array.from([0, 0, 1, 2, 255]));
  assert.equal(base58Encode(new Uint8Array(0)), '');
  const kp = await generateLightweightKeypair();
  const exported = base58Encode(kp.secretKey);
  assert.deepEqual(base58Decode(exported), kp.secretKey, '64 bytes survive the round trip');
  const back = await lightweightKeypairFromSecretKey(base58Decode(exported));
  assert.equal(back.publicKey.toBase58(), kp.publicKey.toBase58(), 'importing the exported key gives the same wallet');
});
