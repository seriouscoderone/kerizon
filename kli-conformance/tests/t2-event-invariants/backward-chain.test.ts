/**
 * Backward hash chain tests: verify that each event's 'p' field
 * (prior event digest) matches the 'd' (SAID) of the preceding event.
 */

import { describe, it } from 'vitest';
import fc from 'fast-check';
import { arbKelSequence } from '../../src/generators/events.js';

const NUM_RUNS = 500;

describe('backward hash chain invariants', () => {
  it('inception has no prior digest', () => {
    fc.assert(
      fc.property(arbKelSequence(0, 3), (events) => {
        const icp = events[0];
        return !('p' in icp) || icp['p'] === undefined || icp['p'] === '';
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('every non-inception event.p == prior event.d', () => {
    fc.assert(
      fc.property(arbKelSequence(2, 8), (events) => {
        for (let i = 1; i < events.length; i++) {
          const priorSaid = events[i - 1]['d'] as string;
          const currentP = events[i]['p'] as string;
          if (currentP !== priorSaid) return false;
        }
        return true;
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('SAID chain is unbroken across the full KEL', () => {
    fc.assert(
      fc.property(arbKelSequence(3, 10), (events) => {
        // Verify: d[0] → p[1], d[1] → p[2], ..., d[n-1] → p[n]
        const saids = events.map(e => e['d'] as string);
        const priors = events.slice(1).map(e => e['p'] as string);

        for (let i = 0; i < priors.length; i++) {
          if (priors[i] !== saids[i]) return false;
        }
        return true;
      }),
      { numRuns: NUM_RUNS },
    );
  });
});
