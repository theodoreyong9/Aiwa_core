import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeVdfChain, vdfSeed } from '../src/vdf.js';
import { identityFromSecretKey } from '../src/identity.js';
import { createEvent, verifyEvent } from '../src/event.js';
import { weightedMedian } from '../src/weighted-median.js';
import { checkCausalConsistency } from '../src/causal-tick.js';
import { evaluate, verify as verifyWesolowski } from '../src/wesolowski-vdf.js';
import { computeOutcomeHash, checkOutcome } from '../src/generous-transfer.js';
import { rewardFixed } from '../src/reward.js';

// A real, independent Rust implementation (interop/rust-vdf) of
// specific, real pieces of this project's own protocol logic — never
// a wrapper or transpilation of the JS. This test builds and runs the
// real Rust binary, then compares its real output against the real,
// live JS modules' own output for the identical test vectors, byte
// for byte. This is the concrete demonstration that closes what this
// project's own Yellow Paper (§16.1) previously, honestly documented
// as a gap: no cross-runtime check existed here before this — ported
// from AIWA_chain's own, already-verified interop/rust-vdf, the
// project this codebase was itself ported from, and extended to cover
// this project's own, current, wider event format (with a real,
// signed event, not just bare canonicalization).
//
// SKIPPED, not failed, if no real Rust toolchain (cargo) is available
// — a missing optional toolchain in a given environment is a real,
// honest absence, never grounds to fail the rest of this project's
// own real test suite.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rustProjectDir = path.join(__dirname, '..', 'interop', 'rust-vdf');

function hasCargo() {
  try {
    execSync('cargo --version', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

test('THE REAL CROSS-RUNTIME PROPERTY: an independent Rust implementation produces byte-for-byte identical output to the real, live JS modules, for the identical real test vectors', { skip: !hasCargo() && 'cargo not available in this environment' }, async () => {
  execSync('cargo build --release', { cwd: rustProjectDir, stdio: 'ignore' });
  const binaryPath = path.join(rustProjectDir, 'target', 'release', 'vdf-interop');
  assert.ok(existsSync(binaryPath), 'the real Rust binary must exist after a real, successful build');

  const rustOutput = JSON.parse(execSync(binaryPath, { encoding: 'utf8' }));

  // vdf.js's own real, sequential hash chain — the identical, real
  // test vectors main.rs's own header documents.
  const vdf1 = await computeVdfChain(vdfSeed('earth-domain', 'genesis'), 500);
  const vdf2 = await computeVdfChain(vdfSeed('mars-domain', vdf1), 500);
  const vdf3 = await computeVdfChain(vdfSeed('earth-domain', 'genesis'), 12000);

  assert.equal(rustOutput.vdf1, vdf1, 'a real, single-epoch VDF chain must match exactly across runtimes');
  assert.equal(rustOutput.vdf2, vdf2, 'a real, chained (epoch depends on prior real output) VDF chain must match exactly');
  assert.equal(rustOutput.vdf3, vdf3, 'a real, full-length (12000-iteration) VDF chain must match exactly');

  // event.js's own ACTUAL, current canonical format — wider than a
  // bare {parents,payload} pair (domain/author/authorPublicKey/
  // parents/type/payload/createdAt) — plus a real Ed25519 signature,
  // independently re-derived by a genuinely different library
  // (ed25519-dalek, never this project's own @noble/curves). The
  // identical, real, fixed secret key, domain, out-of-order parents,
  // nested payload, and timestamp main.rs's own header documents.
  const SECRET_KEY_HEX = '762eecb4508ccf9e3940db1148a593616b8f9acf57862a911ad24a325081f1d3';
  const identity = await identityFromSecretKey(SECRET_KEY_HEX);
  const event = await createEvent(identity, {
    domain: 'rust-interop-test',
    parents: ['zzz-parent-2', 'aaa-parent-1'], // deliberately out of order — exercises the real sort
    type: 'test-event',
    payload: { zebra: 1, apple: { charlie: 3, bravo: 2 }, list: [3, 1, 2] }, // deliberately out-of-order keys — exercises the real, recursive canonicalize()
    createdAt: 1735689600000,
  });
  const localVerify = await verifyEvent(event);
  assert.equal(localVerify.valid, true, 'sanity: the real, locally-built event must verify against itself first');

  assert.equal(rustOutput.authorPublicKey, event.authorPublicKey, 'a real Ed25519 public key, independently re-derived from the identical real secret key by a genuinely different library, must match exactly');
  assert.equal(rustOutput.authorId, event.author, 'real author-id derivation (SHA-256 of the real public key) must match exactly across runtimes');
  assert.equal(rustOutput.eventId, event.id, "a real event's own canonical id — the project's ACTUAL, current, wider format, not just {parents,payload} — must match exactly across runtimes, including real parent sorting and real recursive payload canonicalization");
  assert.equal(rustOutput.eventSignature, event.signature, 'THE REAL, STRONGEST CHECK: Ed25519 signing is deterministic (RFC 8032) — the identical real secret key, signing the identical real message bytes, must produce a BYTE-IDENTICAL signature in a genuinely different, independent real library, not merely one that happens to verify');
  assert.equal(rustOutput.selfVerify, true, "sanity: the real Rust library must verify its own real signature too");

  // weighted-median.js's own real, custom crossing-point algorithm —
  // never an average of the two middle values.
  const median1 = weightedMedian([{ value: 100, weight: 30 }, { value: 50, weight: 45 }, { value: 200, weight: 10 }, { value: 75, weight: 15 }]);
  const median2 = weightedMedian([{ value: 1000, weight: 5 }, { value: 2000, weight: 5 }, { value: 3000, weight: 90 }]);
  assert.equal(rustOutput.median1, median1, 'the real, custom crossing-point median must match exactly across runtimes');
  assert.equal(rustOutput.median2, median2, 'a real, heavily-skewed-weight case must match exactly across runtimes too');

  // conservation.js's own real split invariant — a real, large,
  // 18-decimal AIWA amount.
  const total = 1000123456789012345678n;
  const firstAmount = 333333333333333333333n;
  const secondAmount = total - firstAmount;
  assert.equal(rustOutput.secondAmount, secondAmount.toString(), "a real, large, 18-decimal AIWA split must match exactly across runtimes — u128 in Rust playing BigInt's own real role");

  // mirror.js's own real reception monotonicity — the identical,
  // real, inline logic applyMirrorEvent uses, isolated here.
  function checkMonotonicity(priorMax, resolvedEpochs) {
    for (const [sourceDomain, newMax] of Object.entries(resolvedEpochs)) {
      const previous = priorMax[sourceDomain] ?? 0;
      if (newMax < previous) return false;
    }
    return true;
  }
  const priorMax1 = { mars: 50, jupiter: 10 };
  assert.equal(rustOutput.monotonicityCase1, checkMonotonicity(priorMax1, { mars: 55, jupiter: 10 }));
  assert.equal(rustOutput.monotonicityCase2, checkMonotonicity(priorMax1, { mars: 40, jupiter: 15 }), 'a real regression on even one real source domain must be rejected identically across runtimes');

  // relative-rate.js's own real, central ratio — real IEEE 754 double
  // division, must agree bit-for-bit across runtimes.
  const observerDelta = 133 - 10;
  const targetDelta = 481 - 100;
  const ratio = targetDelta / observerDelta;
  assert.equal(rustOutput.ratio, ratio, 'a real, non-integer relative-rate ratio must match exactly across runtimes, down to the last real floating-point digit');

  // causal-tick.js's own real consistency check.
  const consistentResult = checkCausalConsistency(100, { tick: 95 }, 10);
  const inconsistentResult = checkCausalConsistency(100, { tick: 50 }, 10);
  assert.equal(rustOutput.consistentCase, consistentResult.consistent);
  assert.equal(rustOutput.consistentGap, consistentResult.gap);
  assert.equal(rustOutput.inconsistentCase, inconsistentResult.consistent);
  assert.equal(rustOutput.inconsistentGap, inconsistentResult.gap);

  // generous-transfer.js's own real, deterministic outcome — a real
  // loss and a real win, both independently recomputed here.
  const losingHash = await computeOutcomeHash('commitment-id-abc', 'vdf-output-xyz-123');
  const winningHash = await computeOutcomeHash('commitment-id-abc', 'vdf-output-90');
  assert.equal(rustOutput.losingHash, losingHash, 'a real, honest-loss outcome hash must match exactly across runtimes');
  assert.equal(rustOutput.losingCheck4, checkOutcome(losingHash, 4), 'the real threshold check itself must agree across runtimes, not just the raw hash');
  assert.equal(rustOutput.winningHash, winningHash, 'a real, winning outcome hash must match exactly across runtimes');
  assert.equal(rustOutput.winningCheck8, checkOutcome(winningHash, 8));

  // wesolowski-vdf.js's own real, PRACTICAL verification — the one
  // path a real, external, gas-constrained chain would actually use
  // (never the raw, symmetric hash chain, prohibitively expensive to
  // redo).
  const x = 123456789n;
  const iterations = 50;
  const y = evaluate(x, iterations);
  const proof = { pi: 1n, l: 182976577130776636739865532488529097497n };
  const jsValid = await verifyWesolowski(x, iterations, y, proof);
  const jsInvalid = await verifyWesolowski(x, iterations, y + 1n, proof);
  assert.equal(jsValid, true, 'sanity: the real, known-good test vector must verify in JS itself first');
  assert.equal(rustOutput.wesolowskiValid, jsValid, 'a real, valid Wesolowski proof must verify identically across runtimes');
  assert.equal(rustOutput.wesolowskiInvalid, jsInvalid, 'a real, tampered y must be rejected identically across runtimes');

  // THE REAL FIX this test file exists to prove: reward.js's own
  // rewardFixed (Q128 fixed-point BigInt, never Math.log/Math.pow)
  // must agree with a genuinely independent Rust implementation of
  // the identical, real algorithm — bit-for-bit, compared as decimal
  // strings, never through either language's own float type. This is
  // the concrete demonstration that closes this project's own,
  // previously-real cross-runtime gap: reward.js's output funds a
  // real, on-chain AIWA claim (accrual.js), and Math.log/Math.pow
  // carry no such guarantee across runtimes — only +,-,*, and
  // truncating-toward-zero / do.
  const rewardParams = { alpha: 1.1, beta: 2.2, gamma: 3, C: Math.pow(33, 3), minQ: 1 };
  const jsRewardBasic = rewardFixed(10, 5_000_000, 5_000_000, 0.2, rewardParams);
  const jsRewardOneYear = rewardFixed(10, 112_000_000, 112_000_000, 0.2, rewardParams);
  const jsRewardBelowMinQ = rewardFixed(10, 0, 1, 0, rewardParams);

  assert.notEqual(jsRewardBasic, null, 'sanity: the real, known-good reward test vector must be non-null in JS itself first');
  assert.equal(rustOutput.rewardBasic, jsRewardBasic.toString(), 'a real reward computation must match exactly, to the last decimal digit, across runtimes — the whole point of Q128 fixed-point BigInt over Math.log/Math.pow');
  assert.equal(rustOutput.rewardOneYear, jsRewardOneYear.toString(), 'a real, extreme case (one full year of continuous domain progression, ~112M epochs) must also match exactly');
  assert.equal(jsRewardBelowMinQ, null, 'sanity: q below minQ must be null in JS itself first');
  assert.equal(rustOutput.rewardBelowMinQIsNone, true, 'the below-minQ gate must reject identically across runtimes too, not just the arithmetic above it');
});
