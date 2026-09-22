// A real, concrete answer to a real, parameter-dependent question:
// does identity-cost.js's churn cost curve actually make repeatedly
// abandoning an aging domain for a fresh one net-unprofitable, given
// a specific deployment's real reward parameters?
//
// This is NOT a structural guarantee the way progression's own
// epoch-cannot-skip-ahead property is. Whether churn is profitable is
// a genuine economic question — the reward formula's own A-denominator
// gives a real, measured advantage to a young domain; identity-cost.js's
// burn requirement makes repeating that advantage cost something, but
// "costs something" and "costs enough" are different claims. This
// module computes the real, honest answer for a given, concrete set
// of parameters — it never asserts churn is unprofitable in general.

import { reward } from './reward.js';

/**
 * Compares two real strategies over the identical total real elapsed
 * epochs, for the identical total real committed capital S per cycle:
 *
 * - "stay": commit once, let the position mature the entire span,
 *   claim once at the end. A domain's own age (A) and its own
 *   patience (t) both equal the full span, since it never resets.
 * - "churn": commit S again every `churnInterval` epochs in a fresh
 *   domain, paying a real burn cost every time, claiming at the end
 *   of each real interval before abandoning that domain. A and t both
 *   equal only the interval each time — the young-domain reward
 *   advantage this real churn cost curve exists specifically to make
 *   not worth exploiting.
 *
 * Real slot-to-epoch correspondence is simplified 1:1 — a real
 * deployment's own actual timing may differ; treat this as a
 * real, order-of-magnitude tool, not an exact prediction.
 *
 * @returns {{
 *   stayReward: number, stayNet: number,
 *   churnCycles: number, churnGrossReward: number, churnTotalCost: number, churnNet: number,
 *   churnProfitable: boolean, advantageRatio: number
 * }}
 */
export function compareChurnVsStay(rewardParams, churnCostCurve, { S, totalEpochs, churnInterval, genesisSlot = 0 }) {
  if (!(totalEpochs > 0)) throw new Error('totalEpochs must be positive');
  if (!(churnInterval > 0)) throw new Error('churnInterval must be positive');
  if (!(S > 0)) throw new Error('S must be positive');

  const stayBurnCost = churnCostCurve(0 - genesisSlot);
  const stayReward = reward(S, totalEpochs, totalEpochs, 0, rewardParams);
  const stayNet = stayReward - stayBurnCost;

  const churnCycles = Math.floor(totalEpochs / churnInterval);
  let churnGrossReward = 0;
  let churnTotalCost = 0;
  for (let cycle = 0; cycle < churnCycles; cycle++) {
    const slotAtThisCycle = cycle * churnInterval - genesisSlot;
    churnTotalCost += churnCostCurve(slotAtThisCycle);
    churnGrossReward += reward(S, churnInterval, churnInterval, 0, rewardParams);
  }
  const churnNet = churnGrossReward - churnTotalCost;

  return {
    stayReward, stayNet,
    churnCycles, churnGrossReward, churnTotalCost, churnNet,
    churnProfitable: churnNet > stayNet,
    advantageRatio: stayNet !== 0 ? churnNet / stayNet : (churnNet > 0 ? Infinity : 0),
  };
}

/**
 * Sweeps a real range of churn intervals and reports whether ANY of
 * them beats staying — the real, practical question a deployer needs
 * answered, since a single interval passing the "unprofitable" check
 * says nothing about a different interval.
 */
export function findMostProfitableChurnInterval(rewardParams, churnCostCurve, { S, totalEpochs, candidateIntervals, genesisSlot = 0 }) {
  let best = null;
  for (const interval of candidateIntervals) {
    if (interval <= 0 || interval > totalEpochs) continue;
    const result = compareChurnVsStay(rewardParams, churnCostCurve, { S, totalEpochs, churnInterval: interval, genesisSlot });
    if (!best || result.churnNet > best.churnNet) best = { interval, ...result };
  }
  return best;
}
