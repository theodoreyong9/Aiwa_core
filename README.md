# aiwa-core

Commitment, state, epoch, transition, VDF, proof, verification,
progression. Pure — no transport, no GUN, no GitHub, no YourMine, no
Jobber. Self-contained: no dependency on any repo outside this stack.

## What's here

- **Event/identity substrate** (`identity.js`, `event.js`,
  `event-log.js`, `materializer.js`, `data-store.js`) — Ed25519
  identities that sign events and capabilities; a canonical,
  content-addressed, self-verifying event (the signer's public key
  travels inside the event, checked against the claimed author id, so
  `EventLog.append()` never trusts an unverified event regardless of
  source); a deliberately "stupid" `EventLog` (memory or IndexedDB
  backend); a `DataStore` — a rebuildable projection over the log via a
  pluggable `Materializer`, never itself the source of truth.
- **Math primitives** (`bigint-math.js`, `fixed-point-math.js`, `units.js`) —
  deterministic BigInt modular exponentiation, primality testing, and a Q128
  fixed-point `ln`/`exp`/`pow` that agrees bit-for-bit across runtimes,
  unlike `Math.log`/`Math.pow`. `units.js` is 18-decimal AIWA amounts,
  string-based conversion, never float multiplication.
- **VDFs** (`vdf.js`, `wesolowski-vdf.js`) — a simple sequential hash chain
  (cheap to build, costs what it took to verify) and a real asymmetric
  Wesolowski VDF (expensive to produce, `O(log T)` to verify) over the
  RSA-2048 Factoring Challenge modulus.
- **Solana-specific identity** (`solana-wallet.js`, `identity-cost.js`,
  `hardware-attestation.js`) — Ed25519 keypair derivation (fresh, from a
  secret key, from a passphrase, from a standard BIP39 mnemonic at
  Solana's own derivation path), Solana burn-transaction construction for
  identity activation cost, and optional two-hop hardware-root
  attestation. `toIdentity(keypair)` bridges a derived keypair into this
  package's own `identity.js` `Identity` — same seed, so a domain built
  here can sign events and capabilities directly.
- **Progression, reward, accrual, conservation, wallet** — the economic
  core: a domain's VDF-bound progression epoch, a reproducible Q128 reward
  formula, position/patience accounting, a Deactivate→Prove→Verify→Consume→Activate
  conservation protocol for claims, and a wallet layer composing both plus
  signed transfer/split — plus real delegation (`issueDelegation`/
  `buildSignedDelegatedTransferEvent`): "sign once, then click as many
  times as you want." A real claim owner signs ONE delegation
  (`{delegate, from}`, no amount cap, no expiry by design — a
  deployment wanting either layers it into its own `contractVerifiers`
  via `'contract-payout'` instead of forcing it on every caller here),
  and a delegate key can then move that owner's already-owned claims
  repeatedly, each a fresh, cheap, independently-signed
  `'delegated-transfer'` event, without the owner's own root key
  signing again. No funds move anywhere at delegation time — nothing is
  pre-funded into a separate account; the delegate only ever authorizes
  moving what the owner already, genuinely owns, one real transfer at a
  time. `wallet.js`'s own header comment covers the exact two-signature
  scheme and why both the embedded delegation signature and the
  transfer's own signer must be checked separately (skipping either is
  the identical impersonation hole `aiwa-lib`'s own `contract.js`
  documents for a naively-trusted `payload.from`).
- **Trust and rate** (`causal-tick.js`, `relative-rate.js`) — a
  weighted-median "Causal Tick" (what other domains, weighted by
  committed capital, corroborate about a domain's position) and a
  clock-free relative-rate mechanism (structural ratios between two
  signed progression witnesses, never a timestamp).
- **Mirror** (`mirror.js`) — mandatory signed per-epoch reception
  commitments with monotonicity, plus `buildReceptionCommitment`, the
  signing half (adapted from the app layer this was ported from, since a
  generic library has no business signing on an app's behalf without
  being asked).
- **Contracts** (`contract-registry.js`, `contract-scan.js`,
  `matching-contract.js`, `generous-transfer.js`) — publishing/verifying
  a contract's own source against a pinned hash, generic event-scanning
  helpers three separate contracts used to reimplement by hand, and two
  real, composed example contracts (a deterministic "generous send"
  bonus gated on a future VDF output, and a third-party matching
  contract that composes with it via a direct function call — no shared
  execution environment, so "composing" only ever means an ordinary
  import).
- **Churn analysis** (`churn-analysis.js`) — answers the concrete,
  parameter-dependent question of whether a deployment's identity-cost
  curve actually makes repeatedly abandoning an aging domain
  unprofitable.

## Where the event/identity substrate came from

`identity.js`/`event.js`/`event-log.js`/`materializer.js`/`data-store.js`
started as a direct copy of [`theodoreyong9/record`](https://github.com/theodoreyong9/record)
— an existing, tested, shared foundation across this portfolio, used as
a reference rather than reinvented from scratch. Record itself is not
one of this stack's own repos, so its code lives here as this package's
own files, not as a live dependency: this repo is self-contained, and
any future divergence between the two is expected and fine. `domain-id.js`'s
old `deriveDomainId(publicKeyBytes)` is this file's own `deriveId` —
identical SHA-256-of-pubkey derivation, not duplicated a second time
under a different name.

## `adapt-event.js` — the one seam

The reducers below (`progression`, `accrual`, `wallet`, `causal-tick`,
`mirror`, the contracts) share a simple internal event convention:
`{id, parents, payload}`, with `payload.type` selecting the reducer
branch. `event.js`'s own wire event is richer —
`{id, domain, author, authorPublicKey, parents, type, payload, createdAt, signature}`,
with `type` as a top-level field. `toReducerEvent`/`toReducerEvents`
bridge the two. This keeps every reducer a near-verbatim, independently
testable state machine — signature/author bytes are a replication and
verification concern, not something every fold needs to carry.

`contract-registry.js`'s `publishContractSpec` is the one function that
actually writes to an `event-log.js` `EventLog` (via `createEvent` +
`log.append`) rather than only reading reducer-shaped events — publishing
a new contract-spec event needs a real signing identity, which the other,
purely-reducing modules never do.

## `createIndexedDbBackend` — verified against a real browser

`event-log.js`'s IndexedDB backend can't be exercised by `node --test`
at all (Node has no IndexedDB) — `test-browser/indexeddb.html` is a
real, runnable check against an actual browser instead: writes two
real, signed events via `createIndexedDbBackend`, then a genuinely
fresh page navigation (new JS context, nothing carried over in
memory) reads them back through a brand-new `EventLog` instance
pointed at the same database name. Run via Playwright against a real
Chromium (needs a static file server — ES modules and IndexedDB both
refuse a `file://` origin):

```
python3 -m http.server 8934   # from this repo's own root
```
then open `http://127.0.0.1:8934/test-browser/indexeddb.html?phase=write`,
then reload the same URL with `?phase=reload`.

Real, confirmed result: both events survived the reload, byte-for-byte,
recovered purely from real IndexedDB storage — not a copied assumption.

## A real bug `head()` had, found via `aiwa-platform`'s own real testing

`EventLog.head()` used to maintain its child-count index as a plain
in-memory `Map`, updated incrementally as `append()` was called. That
map lived on the `EventLog` instance, not the backend — so a **fresh**
`EventLog` constructed over an already-populated, real, persisted
backend (exactly what a page reload, a service worker restart, or a
new process does against real IndexedDB) started with an *empty* index
and silently reported every known event as a head, not just the true
ones. Found while building a service worker in `aiwa-platform` that
constructs a new `EventLog` on every real restart and calls `head()`-
dependent `latestBundle()` — where it manifested concretely as a false
"real fork" error after a restart, on any domain with more than one
published version. Fixed: `head()` now recomputes the child-count index
from the backend on every call, not from any instance-level cache —
`event-log.test.mjs` has a dedicated regression test constructing a
second `EventLog` over the same backend and asserting `head()` stays
correct.

## Honest limits

- `rust-interop.test.mjs` (cross-runtime bit-for-bit verification of
  `fixed-point-math.js`/`reward.js` against an independent Rust port)
  isn't ported — it depends on a Rust reference implementation living at
  a fixed relative path that doesn't exist in this repo. The math itself
  is unchanged from the version that test verified against; a consumer
  wanting that cross-runtime guarantee re-verified should point it at
  their own Rust port.
- `identity-cost.test.mjs`'s incremental-catch-up test and
  `pinned-contract-hashes.test.mjs` depended on app-layer files
  (`identity-cost-view.js`, `app.js`'s own `PINNED_CONTRACT_HASHES`) that
  are this package's consumer's concern, not this package's — dropped,
  not adapted.
- `solana-wallet.js`'s BIP39 test vectors and `wesolowski-vdf.js`'s RSA-2048
  modulus are exactly what they were in the source this was ported from,
  cross-checked the same way (see each file's own header).

## Status

331 passing `node --test` cases. Self-contained — the only external
dependencies are `@noble/curves`, `@noble/hashes`, `@scure/bip39`, and
an optional `@solana/web3.js` peer dependency.

## Testing

```
npm install
node --test
```
