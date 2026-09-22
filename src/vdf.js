// Sequential hash chain: h_0 = SHA-256(seed), h_i = SHA-256(h_{i-1}).
// Each step depends on the output of the one before it — no shortcut,
// regardless of parallel hardware. This bounds the RATE at which a
// domain can advance its own progression; it does not bound calendar
// time, by design.
//
// Not an asymmetric VDF in the cryptographic sense (Wesolowski,
// Pietrzak) — verifying costs exactly what producing costs, not
// asymptotically less. See wesolowski-vdf.js for that. What it does
// provide: production cannot be parallelized or shortcut, with any
// amount of hardware.

async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// A real yield to the browser's macrotask queue — crypto.subtle's own
// promise typically resolves via the microtask queue, which never
// gives the browser a chance to paint, handle input, or process a
// reload request on its own. Thousands of awaited microtasks back to
// back can starve the main thread just as completely as a real
// synchronous loop would, even though every individual step is
// technically async.
function yieldToMain() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

// Binds the chain to one domain and one position in its own history —
// the prior epoch's own output, or 'genesis' for the first. Chaining
// across epochs, not just within one, means epoch N cannot begin
// before epoch N-1 has genuinely finished.
export function vdfSeed(domain, previousOutput) {
  return `${domain}:${previousOutput}`;
}

export async function computeVdfChain(seed, iterations) {
  let h = await sha256(new TextEncoder().encode(seed));
  for (let i = 1; i < iterations; i++) {
    h = await sha256(h);
    if (i % 200 === 0) await yieldToMain();
  }
  return toHex(h);
}

export async function verifyVdfChain(seed, iterations, claimedOutput) {
  if (typeof claimedOutput !== 'string' || !/^[0-9a-f]{64}$/.test(claimedOutput)) return false;
  return (await computeVdfChain(seed, iterations)) === claimedOutput;
}
