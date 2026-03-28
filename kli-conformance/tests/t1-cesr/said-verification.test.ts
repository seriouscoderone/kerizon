import { describe, it } from 'vitest';
import fc from 'fast-check';
import { saidSensitiveToChanges } from '../../src/invariants/said.js';

const NUM_RUNS = 500;

describe('SAID verification invariants', () => {
  it('modifying any value invalidates the SAID', () => {
    fc.assert(saidSensitiveToChanges, { numRuns: NUM_RUNS });
  });
});
