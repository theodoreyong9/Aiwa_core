// Identity activation cost: a real, irrecoverable SOL burn to Solana's
// well-known incinerator address. A burn, not a bond: its protection
// doesn't depend on later enforcement (slashing) ever propagating,
// which matters for a protocol that must keep working through
// arbitrarily long partitions.
//
// This module verifies an already-fetched, normalized transaction
// record — it never touches the network itself.

export const SOLANA_INCINERATOR_ADDRESS = '1nc1nerator11111111111111111111111111111111';

export function initialIdentityCostState() {
  return { registered: {}, usedSignatures: {} };
}

// A deployment-chosen cost curve: burn lamports required as a function
// of slots elapsed since the deployment's own genesis slot. Optional —
// closes a churn attack where abandoning an aged domain for a fresh
// one would otherwise cost nothing beyond the ordinary burn.
export function linearCostCurve({ baseLamports, lamportsPerSlot }) {
  return (slotsSinceGenesis) => baseLamports + Math.max(0, slotsSinceGenesis) * lamportsPerSlot;
}

export function requiredBurnLamports(registrationSlot, genesisSlot, costCurve) {
  if (registrationSlot === null || registrationSlot === undefined || !Number.isFinite(registrationSlot)) return 0;
  return costCurve(Math.max(0, registrationSlot - genesisSlot));
}

export function verifyBurnProof(tx, { minLamports = 0 } = {}) {
  if (tx.err !== null) return { valid: false, reason: 'transaction failed on-chain' };
  if (tx.commitment !== 'finalized') return { valid: false, reason: `commitment is '${tx.commitment}', not 'finalized'` };
  if (!Number.isFinite(tx.incineratorBalanceDeltaLamports) || tx.incineratorBalanceDeltaLamports <= 0) {
    return { valid: false, reason: 'no positive burn detected' };
  }
  if (tx.incineratorBalanceDeltaLamports < minLamports) {
    return { valid: false, reason: `burned ${tx.incineratorBalanceDeltaLamports} lamports, need >= ${minLamports}` };
  }
  return { valid: true };
}

// Accumulates every real, valid burn from a domain — a domain that
// commits additional real capital later must see its real, total
// committed capital reflected, exactly like accrual.js's own `b`
// already does. Each individual burn is still checked against the
// churn cost curve at its own real slot — a real commitment made
// later in protocol time must still meet whatever the curve requires
// at that later time, never grandfathered in at the original
// registration's own, possibly much lower, requirement.
export function registerIdentityCost(state, { domain, tx, minLamports = 0, now = Date.now(), churnConfig } = {}) {
  if (state.usedSignatures[tx.signature]) {
    return { state, accepted: false, reason: `signature ${tx.signature} already used` };
  }

  let effectiveMinLamports = minLamports;
  if (churnConfig) {
    const required = requiredBurnLamports(tx.slot ?? null, churnConfig.genesisSlot, churnConfig.costCurve);
    effectiveMinLamports = Math.max(minLamports, required);
  }

  const check = verifyBurnProof(tx, { minLamports: effectiveMinLamports });
  if (!check.valid) return { state, accepted: false, reason: check.reason };

  const prior = state.registered[domain];
  const totalBurnedLamports = (prior?.burnedLamports ?? 0) + tx.incineratorBalanceDeltaLamports;
  return {
    state: {
      registered: {
        ...state.registered,
        [domain]: {
          domain,
          burnedLamports: totalBurnedLamports,
          signature: tx.signature, // the most recent contributing signature — every real signature that ever contributed remains individually verifiable via usedSignatures
          registeredAt: prior?.registeredAt ?? now, // when this domain FIRST proved identity cost — never moves on a later, additional burn
          slot: prior?.slot ?? (tx.slot ?? null), // the same real, original registration slot
        },
      },
      usedSignatures: { ...state.usedSignatures, [tx.signature]: true },
    },
    accepted: true,
  };
}

export function hasIdentityCost(state, domain) {
  return Boolean(state.registered[domain]);
}
