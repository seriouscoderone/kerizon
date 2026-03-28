/**
 * Field ordering tests: verify that generated events have fields
 * in the correct order as required by the KERI spec.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  arbInceptionEvent,
  arbKelSequence,
  ICP_FIELD_ORDER,
  ROT_FIELD_ORDER,
  IXN_FIELD_ORDER,
} from '../../src/generators/events.js';

const NUM_RUNS = 200;

describe('KERI event field ordering', () => {
  it('inception events have fields in spec order', () => {
    fc.assert(
      fc.property(arbInceptionEvent, (event) => {
        const keys = Object.keys(event);
        const expectedOrder = ICP_FIELD_ORDER.filter(f => f in event);
        for (let i = 0; i < expectedOrder.length; i++) {
          if (keys[i] !== expectedOrder[i]) return false;
        }
        return true;
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('KEL events have correct ilk-specific field order', () => {
    fc.assert(
      fc.property(arbKelSequence(2, 5), (events) => {
        for (const event of events) {
          const ilk = event['t'] as string;
          const keys = Object.keys(event);

          let expected: readonly string[];
          switch (ilk) {
            case 'icp': case 'dip': expected = ICP_FIELD_ORDER; break;
            case 'rot': case 'drt': expected = ROT_FIELD_ORDER; break;
            case 'ixn': expected = IXN_FIELD_ORDER; break;
            default: return false;
          }

          const expectedFiltered = expected.filter(f => f in event);
          for (let i = 0; i < expectedFiltered.length; i++) {
            if (keys[i] !== expectedFiltered[i]) return false;
          }
        }
        return true;
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('all events have version string field first', () => {
    fc.assert(
      fc.property(arbKelSequence(1, 5), (events) => {
        return events.every(e => Object.keys(e)[0] === 'v');
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('all events have ilk field second', () => {
    fc.assert(
      fc.property(arbKelSequence(1, 5), (events) => {
        return events.every(e => Object.keys(e)[1] === 't');
      }),
      { numRuns: NUM_RUNS },
    );
  });
});
