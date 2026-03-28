import { describe, it } from 'vitest';
import fc from 'fast-check';
import {
  singlePrimitiveRoundTrip,
  encodeIdempotent,
  streamRoundTrip,
} from '../../src/invariants/cesr-roundtrip.js';

const NUM_RUNS = 1000;

describe('CESR round-trip invariants', () => {
  it('encode → decode preserves raw bytes and code', () => {
    fc.assert(singlePrimitiveRoundTrip, { numRuns: NUM_RUNS });
  });

  it('encode → decode → encode is idempotent', () => {
    fc.assert(encodeIdempotent, { numRuns: NUM_RUNS });
  });

  it('stream encode → decode → encode round-trips', () => {
    fc.assert(streamRoundTrip, { numRuns: NUM_RUNS });
  });
});
