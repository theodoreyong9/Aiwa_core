# aiwa-core

Validation: commitment, state, epoch, transition, VDF, proof, verification,
progression. Pure — no transport, no storage, no GUN, no GitHub, no
YourMine, no Jobber. Builds on [`@aiwa/record`](https://github.com/theodoreyong9/record)'s
event/identity substrate; never reimplements it.

## What's here

- **Math primitives** (`bigint-math.js`, `fixed-point-math.js`, `units.js`) —
  deterministic BigInt modular exponentiation, primality testing, and a Q128
  fixed-point `ln`/`exp`/`pow` that agrees bit-for-bit across runtimes,
  unlike `Math.log`/`Math.pow`. `units.js` is 18-decimal AIWA amounts,
  string-based conversion, never float multiplication.
- **VDFs** (`vdf.js`, `wesolowski-vdf.js`) — a simple sequential hash chain
  (cheap to build, costs what it took to verify) and a real asymmetric
  Wesolowski VDF (expensive to produce, `O(log T)` to verify) over the
  RSA-2048 Factoring Challenge modulus.
- **Identity** (`solana-wallet.js`, `identity-cost.js`, `hardware-attestation.js`)
  — Ed25519 keypair derivation (fresh, from a secret key, from a
  passphrase, from a standard BIP39 mnemonic at Solana's own derivation
  path), Solana burn-transaction construction for identity activation
  cost, and optional two-hop hardware-root attestation.
  `toRecordIdentity(keypair)` bridges a derived keypair into an
  `@aiwa/record` `Identity` — same seed, so a domain built here can sign
  events and capabilities on the substrate below it.
- **Progression, reward, accrual, conservation, wallet** — the economic
  core: a domain's VDF-bound progression epoch, a reproducible Q128 reward
  formula, position/patience accounting, a Deactivate→Prove→Verify→Consume→Activate
  conservation protocol for claims, and a wallet layer composing both plus
  signed transfer/split.
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

## Why this depends on `@aiwa/record` instead of reimplementing it

`@aiwa/record` already provides a tested, self-verifying event/identity
substrate (`EventLog`, `Identity`, `createEvent`/`verifyEvent`) shared
across this portfolio. Building a second one here would fork the single
source of truth it's meant to be. `domain-id.js`'s old
`deriveDomainId(publicKeyBytes)` is `@aiwa/record`'s own `deriveId` —
identical SHA-256-of-pubkey derivation, not duplicated.

## `adapt-event.js` — the one seam

The reducers below (`progression`, `accrual`, `wallet`, `causal-tick`,
`mirror`, the contracts) share a simple internal event convention:
`{id, parents, payload}`, with `payload.type` selecting the reducer
branch. `@aiwa/record`'s own wire event is richer —
`{id, domain, author, authorPublicKey, parents, type, payload, createdAt, signature}`,
with `type` as a top-level field. `toReducerEvent`/`toReducerEvents`
bridge the two. This keeps every reducer a near-verbatim, independently
testable state machine — signature/author bytes are a replication and
verification concern (`@aiwa/record`'s own job), not something every
fold needs to carry.

`contract-registry.js`'s `publishContractSpec` is the one function that
actually writes to an `@aiwa/record` `EventLog` (via `createEvent` +
`log.append`) rather than only reading reducer-shaped events — publishing
a new contract-spec event needs a real signing identity, which the other,
purely-reducing modules never do.

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

314 passing `node --test` cases. Depends on `@aiwa/record` via its GitHub
URL (neither package is on npm yet).

## Testing

```
npm install
node --test
```
