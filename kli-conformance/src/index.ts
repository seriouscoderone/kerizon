// ── Utilities ──
export { encodeB64, decodeB64, b64Index, b64Value } from './util/base64url.js';
export { digest, DIGEST_CODES } from './util/hash.js';
export type { HashAlgo } from './util/hash.js';
export { CODE_TABLE, encodePrimitive, decodePrimitive, decodeStream, encodeStream } from './util/cesr-codec.js';
export type { CodeEntry, CesrPrimitive } from './util/cesr-codec.js';
export { computeSaid, verifySaid, computeEventSaids } from './util/said.js';

// ── Adapter ──
export type {
  CliAdapter,
  CliResult,
  KeyState,
  KelEvent,
  EventType,
  InceptConfig,
  RotateConfig,
  InteractConfig,
  WitnessHandle,
} from './adapter/types.js';
export { KliAdapter, detectKli, DEMO_WITNESSES } from './adapter/kli-adapter.js';

// ── Generators ──
export {
  arbCesrPrimitive,
  arbCesrStream,
  arbPrimitiveForCode,
  arbVerfer,
  arbDigest,
  arbSignature,
  arbSalt,
  arbDateTime,
} from './generators/cesr.js';
export { arbVerferQb64, arbDigestQb64, arbKeyList, arbDigestList, arbWitnessAid, arbWitnessList } from './generators/keys.js';
export { arbInceptionEvent, arbKelSequence, arbRotationFrom, arbInteractionFrom } from './generators/events.js';

// ── Invariants ──
export { checkSequenceMonotonicity } from './invariants/sequence.js';
export { checkKeyCommitment, checkKeyCommitmentChain } from './invariants/key-commitment.js';
export { checkWitnessThreshold, checkRotationWitnessThreshold, checkWitnessThresholdChain } from './invariants/witness-threshold.js';
export { checkDelegationChain, checkBidirectionalPeg } from './invariants/delegation-chain.js';
export { checkPreRotationChain, checkSaidIntegrity } from './invariants/pre-rotation.js';
export { checkFirstSeenUniqueness, checkSaidUniqueness, checkStrictOrdering, checkAllFirstSeenInvariants } from './invariants/first-seen.js';

// ── Models ──
export {
  initialModel,
  InceptCommand,
  RotateCommand,
  InteractCommand,
  RotateNonTransferableCommand,
  InteractEstOnlyCommand,
  arbTransferableCommands,
  arbNonTransferableCommands,
  arbEstOnlyCommands,
} from './models/kel-state-machine.js';
export type { KelModel } from './models/kel-state-machine.js';

// ── Harness ──
export { execCli, execCliBinary } from './harness/cli-executor.js';
export { createTempEnv } from './harness/temp-env.js';
export type { TempEnv } from './harness/temp-env.js';
export { runConformanceSuite } from './harness/runner.js';
export type { ConformanceResult, SuiteResult } from './harness/runner.js';

// ── Z3 Constraint Models ──
export { proveSaidLengthConstraints, proveSaidDeterminism } from './z3/said-constraints.js';
export { proveSequenceUniqueness, proveGapDetection } from './z3/sequence-constraints.js';
export { proveSimpleThreshold, proveFractionalThreshold, proveWitnessTally } from './z3/threshold-constraints.js';
export { proveCommitmentBinding, proveKeyCountConstraint } from './z3/key-commitment.js';
export { proveBidirectionalPeg, proveSealExactMatch } from './z3/delegation.js';
