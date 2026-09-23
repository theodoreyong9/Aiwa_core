// aiwa-core: commitment, state, epoch, transition, VDF, proof,
// verification, progression — pure, no transport, no GUN, no GitHub,
// no YourMine, no Jobber. Owns the event/identity/storage substrate
// (identity.js/event.js/event-log.js/materializer.js/data-store.js)
// that aiwa-platform and everything above it build on.

export { generateIdentity, identityFromSecretKey, publicIdentity, deriveId, Identity } from './identity.js';
export { createEvent, verifyEvent, computeEventId } from './event.js';
export { EventLog, createMemoryBackend, createIndexedDbBackend } from './event-log.js';
export { defaultKvMaterializer } from './materializer.js';
export { DataStore } from './data-store.js';

export { toReducerEvent, toReducerEvents } from './adapt-event.js';

export { modPow, isProbablePrime, hashToPrime } from './bigint-math.js';
export { FixedPointError, FRAC_BITS, SCALE, mulFixed, divFixed, bitLengthNonNeg, numberToFixed, fixedToNumber, LN2, lnFixed, expFixed, powFixed } from './fixed-point-math.js';
export { DECIMALS, toUnits, fromUnits, fromFloat, fixedToUnits, format } from './units.js';

export { vdfSeed, computeVdfChain, verifyVdfChain } from './vdf.js';
export { RSA_2048_MODULUS, evaluate as wesolowskiEvaluate, prove as wesolowskiProve, verify as wesolowskiVerify } from './wesolowski-vdf.js';

export { weightedMedian } from './weighted-median.js';

export {
  generateLightweightKeypair, lightweightKeypairFromSecretKey, deriveKeypairFromPassphrase,
  deriveKeypairFromBip39Mnemonic, validateBip39Mnemonic, generateKeypair, keypairFromSecretKey,
  encryptSecretKey, decryptSecretKey, buildBurnTransaction, buildTransferTransaction,
  signAndSerialize, broadcastBurnTransaction, broadcastTransferTransaction, loadSolanaWeb3,
  toIdentity,
} from './solana-wallet.js';

export {
  SOLANA_INCINERATOR_ADDRESS, initialIdentityCostState, linearCostCurve,
  requiredBurnLamports, verifyBurnProof, registerIdentityCost, hasIdentityCost,
} from './identity-cost.js';
export {
  issueHardwareRoot, bindHardwareRoot, verifyHardwareAttestation, isIndependenceAttested, MIN_INDEPENDENT_ROOTS,
} from './hardware-attestation.js';

export { initialProgressionState, applyProgressionEvent, materializeProgression } from './progression.js';
export { RewardError, rewardFixed, reward, elapsedEpochs, domainAge } from './reward.js';
export {
  initialAccrualState, applyAccrualEvent, materializeAccrual, claimableNow,
  buildSignedAccrualEvent, buildSignedClaimEvent,
} from './accrual.js';
export {
  initialConservationState, issueClaim, splitClaim, deactivate, proveTransfer,
  verify as verifyConservationProof, consume, activate, transfer, identityDerivation,
} from './conservation.js';
export {
  initialWalletState, buildSignedTransferEvent, buildSignedSplitEvent, applyWalletEvent,
  materializeWallet, spendableClaims, totalBalance,
  issueDelegation, buildSignedDelegatedTransferEvent, buildSignedDelegatedSplitEvent,
  deriveVoucherAddress, buildSignedVoucherRedeemEvent, buildSignedDelegatedVoucherRedeemEvent,
} from './wallet.js';


export {
  initialMirrorState, canonicalReceptionMessage, buildReceptionCommitment, applyMirrorEvent,
  deriveSourceEpochLookup, materializeMirror, computeResidualDiversity,
} from './mirror.js';
export { computeCausalTick, checkCausalConsistency } from './causal-tick.js';
export {
  buildRateWitness, verifyRateWitness, computeRelativeRate, computeEmergentRate, composeRelativeRates,
} from './relative-rate.js';

export {
  computeContractHash, publishContractSpec, readContractSource, verifyContractSource,
  scanContractSpecs, registerVerifiedContract,
} from './contract-registry.js';
export { collectProgressionParentIds, groupEventsByKey } from './contract-scan.js';
export {
  CONTRACT_ID as GENEROUS_TRANSFER_CONTRACT_ID, buildGenerousSendCommitment, verifyGenerousSendSignature,
  computeOutcomeHash, checkOutcome, verifyQualifyingEpoch, resolveGenerousSend,
  verifyPayout as verifyGenerousTransferPayout, buildOfferPayload,
} from './generous-transfer.js';
export {
  CONTRACT_ID as MATCHING_CONTRACT_ID, buildMatchCommitment, verifyMatchCommitmentSignature,
  verifyPayout as verifyMatchingContractPayout,
} from './matching-contract.js';
export { compareChurnVsStay, findMostProfitableChurnInterval } from './churn-analysis.js';
