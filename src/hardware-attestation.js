// A domain's minimal independence hypothesis: attestation that it is
// not backed solely by an actor who can fabricate arbitrary
// identities and observations in software alone. This is a real,
// binary GATE on observation eligibility that causal-tick.js reports
// as a SEPARATE signal — never a weight, never a vote, never itself
// the source of Causal Tick's own value. AIWA works fully without it.
//
// A real, two-hop signature chain:
//   origin domain --[issues]--> hardware root --[binds]--> this domain
//
// HONEST LIMIT: nothing here can verify from software alone that a
// hardware root's signing key really lives on real, non-clonable
// hardware. What this DOES verify is a real, traceable chain of
// signatures from a known origin.

const MIN_INDEPENDENT_ROOTS = 2;

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function canonicalIssuance({ originDomain, hardwareRootPubkey, issuedAt, nonce }) {
  return JSON.stringify({ originDomain, hardwareRootPubkey, issuedAt, nonce });
}
function canonicalBinding({ hardwareRootPubkey, boundDomain, boundAt }) {
  return JSON.stringify({ hardwareRootPubkey, boundDomain, boundAt });
}

export async function issueHardwareRoot(originKeypair, originDomain, hardwareRootPubkeyBytes, { issuedAt = Date.now(), nonce = crypto.randomUUID() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const fields = { originDomain, hardwareRootPubkey: toHex(hardwareRootPubkeyBytes), issuedAt, nonce };
  const message = new TextEncoder().encode(canonicalIssuance(fields));
  const signature = ed25519.sign(message, originKeypair.secretKey.slice(0, 32));
  return { ...fields, originSignature: toHex(signature), originSignerPubkey: toHex(originKeypair.publicKey.toBytes()) };
}

export async function bindHardwareRoot(hardwareRootSecretKey, hardwareRootPubkeyBytes, boundDomain, { boundAt = Date.now() } = {}) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const fields = { hardwareRootPubkey: toHex(hardwareRootPubkeyBytes), boundDomain, boundAt };
  const message = new TextEncoder().encode(canonicalBinding(fields));
  const signature = ed25519.sign(message, hardwareRootSecretKey);
  return { ...fields, bindingSignature: toHex(signature) };
}

export async function verifyHardwareAttestation(attestation, expectedDomain) {
  const { ed25519 } = await import('@noble/curves/ed25519.js');
  const { deriveId } = await import('@aiwa/record');
  const { issuance, binding } = attestation ?? {};
  if (!issuance || !binding) return false;
  if (binding.boundDomain !== expectedDomain) return false;
  if (binding.hardwareRootPubkey !== issuance.hardwareRootPubkey) return false;

  try {
    // The signing key must really BE the claimed origin's own key —
    // not merely a valid signature by SOME key.
    if ((await deriveId(fromHex(issuance.originSignerPubkey))) !== issuance.originDomain) return false;

    const issuanceMessage = new TextEncoder().encode(canonicalIssuance(issuance));
    const issuanceValid = ed25519.verify(fromHex(issuance.originSignature), issuanceMessage, fromHex(issuance.originSignerPubkey));
    if (!issuanceValid) return false;

    const bindingMessage = new TextEncoder().encode(canonicalBinding(binding));
    const bindingValid = ed25519.verify(fromHex(binding.bindingSignature), bindingMessage, fromHex(binding.hardwareRootPubkey));
    if (!bindingValid) return false;
  } catch {
    return false;
  }

  return true;
}

export async function isIndependenceAttested(attestations, domain) {
  const distinctRoots = new Set();
  for (const attestation of attestations ?? []) {
    if (await verifyHardwareAttestation(attestation, domain)) {
      distinctRoots.add(attestation.binding.hardwareRootPubkey);
    }
  }
  return distinctRoots.size >= MIN_INDEPENDENT_ROOTS;
}

export { MIN_INDEPENDENT_ROOTS };
