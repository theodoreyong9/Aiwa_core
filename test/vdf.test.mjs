import { test } from 'node:test';
import assert from 'node:assert/strict';
import { vdfSeed, computeVdfChain, verifyVdfChain } from '../src/vdf.js';

test('vdfSeed binds a chain to exactly one domain and one position', () => {
  assert.notEqual(vdfSeed('a', 'genesis'), vdfSeed('b', 'genesis'));
  assert.notEqual(vdfSeed('a', 'genesis'), vdfSeed('a', 'other'));
});

test('computeVdfChain is deterministic', async () => {
  const seed = vdfSeed('d', 'genesis');
  const out1 = await computeVdfChain(seed, 500);
  const out2 = await computeVdfChain(seed, 500);
  assert.equal(out1, out2);
});

test('computeVdfChain output is a real 64-char hex SHA-256 digest', async () => {
  const out = await computeVdfChain(vdfSeed('d', 'genesis'), 500);
  assert.match(out, /^[0-9a-f]{64}$/);
});

test('a different seed produces a different chain for the same iteration count', async () => {
  const out1 = await computeVdfChain(vdfSeed('a', 'genesis'), 500);
  const out2 = await computeVdfChain(vdfSeed('b', 'genesis'), 500);
  assert.notEqual(out1, out2);
});

test('a different iteration count produces a different output for the same seed — genuinely sequential', async () => {
  const seed = vdfSeed('d', 'genesis');
  const out500 = await computeVdfChain(seed, 500);
  const out501 = await computeVdfChain(seed, 501);
  assert.notEqual(out500, out501);
});

test('verifyVdfChain accepts a genuinely computed chain', async () => {
  const seed = vdfSeed('d', 'genesis');
  const out = await computeVdfChain(seed, 500);
  assert.equal(await verifyVdfChain(seed, 500, out), true);
});

test('SECURITY: verifyVdfChain rejects a fabricated output', async () => {
  const seed = vdfSeed('d', 'genesis');
  assert.equal(await verifyVdfChain(seed, 500, 'f'.repeat(64)), false);
});

test('SECURITY: verifyVdfChain rejects a chain computed for fewer iterations than claimed', async () => {
  const seed = vdfSeed('d', 'genesis');
  const shortcut = await computeVdfChain(seed, 400);
  assert.equal(await verifyVdfChain(seed, 500, shortcut), false);
});

test('SECURITY: verifyVdfChain rejects a chain computed under the wrong seed', async () => {
  const wrongSeed = await computeVdfChain(vdfSeed('other', 'genesis'), 500);
  assert.equal(await verifyVdfChain(vdfSeed('d', 'genesis'), 500, wrongSeed), false);
});

test('verifyVdfChain rejects malformed claimed output without throwing', async () => {
  const seed = vdfSeed('d', 'genesis');
  assert.equal(await verifyVdfChain(seed, 500, 'not-hex'), false);
  assert.equal(await verifyVdfChain(seed, 500, null), false);
  assert.equal(await verifyVdfChain(seed, 500, 123), false);
});

test('epoch-to-epoch chaining: a later seed genuinely depends on the earlier output', async () => {
  const epoch1Output = await computeVdfChain(vdfSeed('d', 'genesis'), 500);
  const epoch2Seed = vdfSeed('d', epoch1Output);
  const wrongEpoch2Seed = vdfSeed('d', 'f'.repeat(64));
  const real = await computeVdfChain(epoch2Seed, 500);
  const fake = await computeVdfChain(wrongEpoch2Seed, 500);
  assert.notEqual(real, fake);
});
