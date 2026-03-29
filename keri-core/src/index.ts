/**
 * @kerizon/keri-core — KERI key event creation functions.
 */

export { incept } from './events/inception.js';
export { rotate } from './events/rotation.js';
export { interact } from './events/interaction.js';

export type {
  EventType,
  InceptConfig,
  RotateConfig,
  InteractConfig,
} from './events/types.js';

export {
  ICP_FIELDS,
  ROT_FIELDS,
  IXN_FIELDS,
  DIP_FIELDS,
  DRT_FIELDS,
} from './events/types.js';

export { computeNextDigest, verifyPreRotation } from './key-commitment/pre-rotation.js';
export { isTransferable, isTransferableCode } from './key-commitment/transferability.js';

export { Kever } from './state/kever.js';
export { TraitDex } from './state/traits.js';

export { checkDualThreshold } from './thresholds/dual-threshold.js';
export type { DualThresholdResult } from './thresholds/types.js';
export { buildWitnessConfig, applyWitnessChanges, enoughReceipts } from './thresholds/witness-config.js';
export type { WitnessConfiguration } from './thresholds/witness-config.js';
