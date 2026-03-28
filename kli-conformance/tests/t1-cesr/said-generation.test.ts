import { describe, it } from 'vitest';
import fc from 'fast-check';
import {
  saidDeterministic,
  saidComputeVerify,
  saidLength,
  saidStartsWithCode,
  inceptionSaidEquality,
} from '../../src/invariants/said.js';

const NUM_RUNS = 500;

describe('SAID generation invariants', () => {
  it('SAID computation is deterministic', () => {
    fc.assert(saidDeterministic, { numRuns: NUM_RUNS });
  });

  it('computeSaid → verifySaid returns true', () => {
    fc.assert(saidComputeVerify, { numRuns: NUM_RUNS });
  });

  it('SAID has correct length for its code', () => {
    fc.assert(saidLength, { numRuns: NUM_RUNS });
  });

  it('SAID starts with its derivation code', () => {
    fc.assert(saidStartsWithCode, { numRuns: NUM_RUNS });
  });

  it('inception events have d == i after SAIDification', () => {
    fc.assert(inceptionSaidEquality, { numRuns: NUM_RUNS });
  });
});
