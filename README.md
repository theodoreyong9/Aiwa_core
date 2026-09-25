# aiwa-core

Commitment, state, epoch, transition, VDF, proof, verification,
progression. Pure — no transport, no GUN, no GitHub, no YourMine, no
Jobber. Self-contained: no dependency on any repo outside this stack.

## Where this sits

```
       ┌────────────────────────────────────────────────┐
       │ AIWA_project                                   │
       │ one concrete deployment (a single static page, │
       │ no build step, no fixed server)                │
       └────────────────────────────────────────────────┘
                                │
                                │  imports all three, directly
                                ▼
              ┌──────────────────────────────────┐
              ▼                                  ▼
┌───────────────────────────┐      ┌───────────────────────────┐
│ aiwa-lib                  │      │ aiwa-platform             │
│ public wallet API (AIWA), │      │ transport, replication,   │
│ Channel, contract SDK     │      │ capability-gated storage, │
│                           │      │ bundle publishing         │
└───────────────────────────┘      └───────────────────────────┘
              │                                  │
              └────────────────┬─────────────────┘
                               ▼
       ┌──────────────────────────────────────────────┐
       │ aiwa-core  <-- you are here                  │
       │ the protocol itself: identity, event log,    │
       │ progression, accrual, conservation, Mirror,  │
       │ Causal Tick, contracts, delegation, vouchers │
       │                                              │
       │ depends on nothing of its own - only         │
       │ @noble/curves, @noble/hashes, @scure/bip39,  │
       │ optional @solana/web3.js                     │
       └──────────────────────────────────────────────┘
```

Nothing above this package may alter what counts as a valid state
transition — that's the whole point of drawing it at the bottom.
`aiwa-lib`'s `Channel` and bearer vouchers are real protocol
extensions that live here, in `aiwa-core` itself, never layered on top
of it, for exactly this reason.

## What's here

- **Event/identity substrate** (`identity.js`, `event.js`,
  `event-log.js`, `materializer.js`, `data-store.js`) — Ed25519
  identities that sign events and capabilities; a canonical,
  content-addressed, self-verifying event (the signer's public key
  travels inside the event, checked against the claimed author id, so
  `EventLog.append()` never trusts an unverified event regardless of
  source); a deliberately "stupid" `EventLog` (memory or IndexedDB
  backend, both supporting real deletion via `pruneBeforeCheckpoint` —
  see "Checkpoints" below); a `DataStore` — a rebuildable projection
  over the log via a pluggable `Materializer`, never itself the source
  of truth.
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
  core: a domain's VDF-bound progression epoch (real event builders must
  route parents through `progressionParents(heads, lastId)` — see
  "Checkpoints" below for the real bug that omitting it causes), a
  reproducible Q128 reward formula, position/patience accounting
  (`'accrual'`/`'claim'`, each
  requiring a real Ed25519 signature proving the signer controls the
  named domain — see `buildSignedAccrualEvent`/`buildSignedClaimEvent`
  in `accrual.js`, and "Honest limits" below for the real gap this
  closed), a Deactivate→Prove→Verify→Consume→Activate
  conservation protocol for claims, and a wallet layer composing both plus
  signed transfer/split — plus real delegation (`issueDelegation`/
  `buildSignedDelegatedTransferEvent`/`buildSignedDelegatedSplitEvent`):
  "sign once, then click as many times as you want." A real claim owner
  signs ONE delegation (`{delegate, from}`, no amount cap, no expiry by
  design — a deployment wanting either layers it into its own
  `contractVerifiers` via `'contract-payout'` instead of forcing it on
  every caller here), and a delegate key can then move AND split that
  owner's already-owned claims repeatedly, each a fresh, cheap,
  independently-signed `'delegated-transfer'`/`'delegated-split'` event,
  without the owner's own root key signing again. No funds move
  anywhere at delegation time — nothing is pre-funded into a separate
  account; the delegate only ever authorizes moving what the owner
  already, genuinely owns, one real transfer at a time. `wallet.js`'s
  own header comment covers the exact two-signature scheme and why
  both the embedded delegation signature and the transfer's own signer
  must be checked separately (skipping either is the identical
  impersonation hole `aiwa-lib`'s own `contract.js` documents for a
  naively-trusted `payload.from`).
- **A real bearer voucher** (`deriveVoucherAddress`/
  `buildSignedVoucherRedeemEvent`, `'voucher-redeem'`) — a classic
  hash-lock, the same idea a Lightning HTLC or a Bitcoin
  pay-to-hash-of-a-preimage script uses: an ordinary, already-existing
  signed `'transfer'` addressed to the hash of a secret (not any real
  identity) issues the voucher — no new protocol needed there, since
  `owner`/`from`/`to` are opaque strings to `conservation.js`. Redeeming
  reveals that secret in a real, signer-authenticated event. "The QR
  can be copied, but only the first redemption succeeds" falls
  straight out of `conservation.js`'s own existing single-writer
  invariant (`deactivate()` throws on an already-consumed claim) — no
  new double-spend logic was needed to get that property.
  `buildSignedDelegatedVoucherRedeemEvent`/`'delegated-voucher-redeem'`
  extends the identical delegation mechanism below to redemption too:
  a channel's own session key can redeem a voucher, and the value still
  lands in the real owner's identity (`delegation.from`), never the
  delegate's own — the same two-signature composition
  (`delegated-transfer` already uses), since an ordinary
  `verifyVoucherRedemption` requires the real signer to derive the
  claimed destination directly, which a session key never does by
  construction.
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
- **Contracts** (`contract-registry.js`) — publishing/verifying a
  contract's own source against a pinned hash. (Two real, ported
  example contracts — a "generous send" bonus gated on a future VDF
  output, and a third-party matching contract composing with it — plus
  `contract-scan.js`'s own generic event-scanning helpers, factored out
  after those two, were all removed: real, correctly-ported
  functionality, but never exposed by `aiwa-lib` or any app built on
  this, and `contract-scan.js`'s own helpers ended up with no real
  caller even among the contracts that motivated them — dead weight
  here rather than a real product decision.)
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

## Real, verified cross-runtime interoperability

`interop/rust-vdf/` is a real, independent Rust implementation of a
real, growing set of this protocol's own core computations — the
sequential VDF chain, a real, fully signed event's own canonical id
(this project's ACTUAL, current, wider format — `domain`/`author`/
`authorPublicKey`/`parents`/`type`/`payload`/`createdAt`, not a
simplified stand-in), a real Ed25519 signature over that exact event
independently re-derived by a genuinely different library
(`ed25519-dalek`, never this project's own `@noble/curves`), the
weighted median, Conservation's own split invariant, Mirror's own
reception monotonicity, relative-rate's own central ratio, Causal
Tick's own consistency check, the real, *practical* Wesolowski
verification (including real prime-derivation and Miller-Rabin
primality testing), and the reward formula's own Q128 fixed-point
core — each
written from the same specification, never by wrapping or transpiling
the JS. `test/rust-interop.test.mjs` builds it, runs it, and compares
its real output against the real JS modules' own output, byte for
byte, for every one of these — including a genuinely stronger check
than mere signature verification: Ed25519 signing is deterministic
(RFC 8032), so the same secret key signing the same message must
produce a byte-identical signature across two independent libraries,
not merely one that happens to verify. See
`interop/rust-vdf/README.md` for exactly what this does and does not
claim.

Ported from [AIWA_chain's own `interop/rust-vdf`](https://github.com/theodoreyong9/AIWA_chain/tree/main/interop/rust-vdf)
— the project this codebase was itself ported from — after directly
verifying `vdf.js`, `weighted-median.js`, `conservation.js`'s split
invariant, `mirror.js`'s monotonicity check, `relative-rate.js`'s
central ratio, `causal-tick.js`'s consistency check,
`wesolowski-vdf.js`, `bigint-math.js`, and
`reward.js`/`fixed-point-math.js` are algorithmically identical
between the two codebases. `event.js`'s own canonical format genuinely
differs (wider), so that part — together with the real, independently
re-signed Ed25519 signature — is a real, new implementation here, not
carried over.

This closes what this project's own Yellow Paper (§16.1) previously,
honestly documented as a real gap: no cross-runtime check existed
here before this. Skips gracefully (never fails) if no Rust toolchain
(`cargo`) is available in a given environment — a missing optional
toolchain is a real, honest absence, never grounds to fail the rest of
this project's own test suite.

## Checkpoints — bounding unbounded local storage

A continuously-running domain accumulates one event per real
progression epoch plus one per real economic action, forever — a real,
previously-documented, previously-unaddressed limit (Yellow Paper
§12.1). `checkpoint.js` closes it: a real, self-signed event
(`buildCheckpointEvent`) embedding a domain's own already-materialized
wallet state (BigInt-safe serialization — claim amounts and accrual
balances round-trip exactly, never coerced through a lossy float), as
of a real, specific set of log heads (`coveredHeads`).

**Signer-scoped from the start, not fixed after the fact.**
`verifyCheckpoint` demands `event.author === event.payload.domain` —
the identical class of gap `accrual.js`'s own `'claim'`/`'accrual'`
signer-scoping fix closed (see below), applied here from day one
rather than discovered later. `EventLog.append()` already guarantees
`event.author` genuinely derives from `event.authorPublicKey` before
any event is ever stored, so no separate embedded signature is needed
here the way `'claim'`/`'accrual'` need one — a checkpoint is read
directly off the real wire event, before `adapt-event.js`'s own
`toReducerEvent` ever strips `author`.

**`EventLog.pruneBeforeCheckpoint(checkpointId)`** physically deletes
every real event a valid checkpoint's own embedded state already
accounts for, keeping only the checkpoint itself as the new logical
root. A brand-new peer receiving a pruned log needs the one, narrow
exception `EventLog.append()` now makes: a real, valid checkpoint may
be appended even though its own declared parents are unknown — the
identical situation that peer is genuinely in.

**HONEST LIMIT, stated plainly, not hidden.** A checkpoint only ever
lets a domain vouch for *its own* real past. A peer who already
independently verified everything up to a checkpoint loses nothing by
trusting it afterward — it is genuinely their own, already-verified
work, summarized. A brand-new peer who receives *only* a pruned log,
never having seen the original history, can no longer independently
re-derive that summarized state from genesis; they trade full
independent verifiability for a real, signed assertion by the domain's
own key about its own past. That tradeoff is inherent to any
checkpoint/pruning scheme — the identical one Ethereum's own
weak-subjectivity checkpoints make — not a flaw specific to this
implementation. A peer that needs full independent verification should
fetch the pre-pruned history from a peer that still holds it, or the
domain should simply not prune.

Verified directly: `test/checkpoint.test.mjs`'s own "prune-and-resume"
property — materializing from a checkpoint plus only the events after
it produces the identical resulting state a continuous, never-pruned
replay of the same real history would (both sides now assert the real
expected epoch directly, not just equality against each other — see
the bug below, which an equality-only version of this same test would
have silently passed while masking).

**A real bug found and fixed while building this.** A checkpoint's own
embedded `progression.domains[domain].lastId` names whichever
progression event was last accepted *before* the checkpoint — an event
`pruneBeforeCheckpoint` is free to delete once the checkpoint exists.
`checkpointWalletState()` now repoints it to the checkpoint's own real
id, since that event becomes the domain's new causal frontier the
moment it's appended (`EventLog.head()` naturally rolls forward to it).

That fix then exposed a second, unrelated, pre-existing bug — not
specific to checkpoints at all: `progression.js`'s causal-chain check
requires the domain's last accepted progression event to be a *direct*
parent, but every real event builder in this codebase (including
`aiwa-lib`'s own `advanceProgress()`) sets parents to the log's current
heads alone. The instant any other event (a `recordCommitment()`, a
checkpoint) becomes the sole head in between — an entirely ordinary
sequence — that direct link silently breaks, and every progression
event from then on is permanently rejected. The check itself is
correct and intentionally strict (see `progression.test.mjs`'s own
fork-rejection tests); the real fix belongs at construction time, not
in the verification logic: the new `progressionParents(heads, lastId)`
helper honestly declares *both* of a progression event's real causal
dependencies — the log's current tip, and its own type's last accepted
transition — as parents, a real merge rather than a forced choice. Any
real progression-event builder should route its parents through it.

Fixing that then surfaced a *third* bug, in the fix for the first one.
`checkpointWalletState()`'s repoint only ever runs on a **cold load** —
`findLatestCheckpoint`'s raw wire event, read before any peer has
materialized anything. An already-running wallet that itself just
called `checkpoint()` then pruned never goes through that path: its own
in-memory cached state gets the checkpoint folded into it directly, and
`applyWalletEvent` — the reducer `materializeWallet` actually calls —
can never verify a checkpoint at all, because it only ever sees events
already adapted by `toReducerEvent`, which deliberately strips
`event.author` (every other type embeds its own signature *inside*
payload instead, exactly so it survives that stripping — see
`buildSignedAccrualEvent`/`buildSignedClaimEvent` — a checkpoint is the
one type that doesn't, by design). So a checkpoint folded this way was
silently treated as an inert no-op, `lastId` stayed pointed at the now
-pruned event, and `progressionParents()` would try to re-declare that
deleted event as a parent on the very next progression event — a real,
now-unappendable event. New `materializeWalletFromWireEvents()` is the
real fix: it takes **raw**, pre-adaptation wire events (exactly what
`collectAncestors`/`EventLog.get` already return), so a checkpoint's
authenticity can genuinely be checked at its own real position in the
sequence, folding in `applyCheckpointEvent`'s repoint right there
before continuing the ordinary, adapted reducer chain for everything
else. `materializeWallet` itself is unchanged and still correct for
batches that never contain a checkpoint; any caller whose batch might
contain one (any consumer resuming from a log that uses checkpoints at
all) should call `materializeWalletFromWireEvents` instead.

## Honest limits

- `identity-cost.test.mjs`'s incremental-catch-up test and
  `pinned-contract-hashes.test.mjs` depended on app-layer files
  (`identity-cost-view.js`, `app.js`'s own `PINNED_CONTRACT_HASHES`) that
  are this package's consumer's concern, not this package's — dropped,
  not adapted.
- `solana-wallet.js`'s BIP39 test vectors and `wesolowski-vdf.js`'s RSA-2048
  modulus are exactly what they were in the source this was ported from,
  cross-checked the same way (see each file's own header).
- **FIXED, PREVIOUSLY UNDOCUMENTED: `'claim'` and `'accrual'` events
  were not signer-scoped at the reducer level.** Found directly, not
  assumed, while investigating whether a channel's delegated session
  key could already submit a claim: `adapt-event.js`'s `toReducerEvent`
  strips `author` before any reducer ever sees an event (by design, so
  reducers stay pure), and neither `applyWalletEvent`'s `'claim'` case
  nor `applyAccrualEvent`'s checked `payload.domain` against who
  actually signed the outer envelope. Confirmed concretely, with a
  real, standalone script: a completely unrelated identity, with no
  delegation and no relationship to the owner, could sign and submit a
  real `'claim'` event naming someone else's domain, and it was honored
  exactly as if the owner had submitted it themselves. This could never
  steal value (the resulting claim was still owned by the named domain,
  spendable only by its real key) — but it did mean *anyone* could
  trigger a domain's claim and, as a side effect, reset that domain's
  own patience clock (`lastActionEpoch`) without consent, a real,
  narrow griefing vector against the `T` (patience) bonus.
  **Fixed**: `accrual.js` now requires a real Ed25519 signature on both
  `'claim'` and `'accrual'` payloads, checked with the exact same
  `deriveId(signerPubkey) === domain` discipline `wallet.js`'s own
  `'transfer'`/`'split'` already apply — see `buildSignedAccrualEvent`/
  `buildSignedClaimEvent` and their matching `verify*Authorization`
  checks, each also nonce-scoped against replay (`accrual.js`'s own new
  `usedNonces`, independent of `wallet.js`'s conservation-layer one).
  Covered by `accrual.test.mjs`'s and `wallet.test.mjs`'s own
  `SECURITY:` tests for forged and replayed claim/accrual events.
  **Direct consequence, also fixed in the same pass**: `aiwa-lib`'s own
  `Channel.claim()` had been built, in the same session, to deliberately
  rely on the exact gap this closed — a channel's session key isn't the
  domain's real key, so once `'claim'` became signer-scoped, a plain
  `'claim'` from a channel stopped verifying. `buildSignedDelegatedClaimEvent`/
  `'delegated-claim'` extends the identical delegation mechanism
  `'delegated-transfer'`/`'delegated-split'`/`'delegated-voucher-redeem'`
  already use: a channel's session key can trigger a claim, and the
  claimed value still lands under the real owner's domain
  (`delegation.from`), never the delegate's own.

## Status

322 passing `node --test` cases (321 pure-JS, plus a real Rust build+run
cross-check when `cargo` is available — see above). Self-contained —
the only external dependencies are `@noble/curves`, `@noble/hashes`,
`@scure/bip39`, and an optional `@solana/web3.js` peer dependency.

## Testing

```
npm install
node --test
```
