import type { Tholder } from '@kerizon/cesr';
import type { DualThresholdResult } from './types.js';

export function checkDualThreshold(
  signingThreshold: Tholder,
  rotationThreshold: Tholder | null,
  indices: number[],
  ondices: number[],
): DualThresholdResult {
  if (!signingThreshold.satisfy(indices)) {
    return { satisfied: false, reason: 'signing threshold not met' };
  }
  if (rotationThreshold && !rotationThreshold.satisfy(ondices)) {
    return { satisfied: false, reason: 'rotation threshold not met' };
  }
  return { satisfied: true };
}
