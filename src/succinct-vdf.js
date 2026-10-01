// Progression with a proof anyone can check in milliseconds — what makes a domain's age and its time since its last
// action verifiable by a third party (a validator, a registry) without redoing the work.
//
// An epoch is a fixed amount of sequential work: `epochIterations` modular squarings (wesolowski-vdf.js). An event
// may carry k epochs at once: k x epochIterations squarings and ONE proof, however large k is. The starting point of
// the work is derived from the domain and the previous output (vdfSeed), so epochs cannot be computed ahead and
// cannot be borrowed from another domain. Producing costs the squarings (and a second pass for the proof);
// verifying costs a few milliseconds.
//
// Why it exists: the hash-chain VDF of vdf.js is verified by recomputing it (a validator would pay as much as the
// domain did), and its iteration count was whatever the signer wrote: one hash per "epoch" was accepted, so age
// could be inflated for nothing. A deployment that sets `rewardParams.epochIterations` fixes the work of an epoch
// and requires this proof.

import { RSA_2048_MODULUS, verify, evaluateAsync, proveAsync } from './wesolowski-vdf.js';

const N = RSA_2048_MODULUS;

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The group element the work of an epoch starts from: bound to the domain and to everything it already did. */
export async function seedToGroupElement(seed) {
  return (BigInt('0x' + (await sha256Hex(seed))) % (N - 3n)) + 2n;
}

// Canonical hex: lower case, no leading zeros, bounded — one representation per value, so an output cannot be
// written two ways (y and y + N would both verify).
function parseHex(value, maxLength) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return null;
  if (!/^[0-9a-f]+$/.test(value) || (value.length > 1 && value[0] === '0')) return null;
  return BigInt('0x' + value);
}

/** Checks the proof that `iterations` sequential squarings, started from `seed`, gave `outputHex`. Cheap. */
export async function verifySuccinctEpochs(seed, iterations, outputHex, proof) {
  if (!Number.isSafeInteger(iterations) || iterations < 1) return false;
  const y = parseHex(outputHex, 512);
  const pi = parseHex(proof?.pi, 512);
  const l = parseHex(proof?.l, 32);
  if (y === null || pi === null || l === null) return false;
  if (y < 2n || y >= N || pi >= N) return false;
  const x = await seedToGroupElement(seed);
  return verify(x, iterations, y, { pi, l }, N);
}

/** Does the work: `iterations` squarings from `seed`, then the proof. Yields to the event loop as it goes. */
export async function computeSuccinctEpochs(seed, iterations, { chunk } = {}) {
  const x = await seedToGroupElement(seed);
  const y = await evaluateAsync(x, iterations, N, chunk);
  const { pi, l } = await proveAsync(x, iterations, y, N, chunk);
  return { vdfOutput: y.toString(16), vdfProof: { pi: pi.toString(16), l: l.toString(16) } };
}
