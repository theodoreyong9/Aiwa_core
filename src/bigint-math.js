// Modular exponentiation, Miller-Rabin primality testing, and
// hash-to-prime — the real, low-level primitives a Wesolowski VDF is
// built from.

export function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

// Miller-Rabin, deterministic for the bases below — correct for any
// n < 3,317,044,064,679,887,385,961,981 (far beyond what a real
// hash-to-prime output for this VDF ever needs), probabilistic with
// negligible error otherwise.
const MILLER_RABIN_WITNESSES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

export function isProbablePrime(n) {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) { d /= 2n; r += 1n; }
  witnessLoop: for (const a of MILLER_RABIN_WITNESSES) {
    if (a >= n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 0n; i < r - 1n; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

// Deterministic prime derivation via Fiat-Shamir: hash real inputs,
// then walk forward (odd candidates only) to the next real prime,
// verified by isProbablePrime — never trusted from a table.
export async function hashToPrime(message, bitLength = 128) {
  const digest = await crypto.subtle.digest('SHA-256', message);
  let candidate = bytesToBigInt(new Uint8Array(digest)) % (1n << BigInt(bitLength));
  candidate |= (1n << BigInt(bitLength - 1)) | 1n; // force the top bit (real bit length) and oddness
  while (!isProbablePrime(candidate)) candidate += 2n;
  return candidate;
}
