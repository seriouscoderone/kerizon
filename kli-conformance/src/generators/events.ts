/**
 * fast-check arbitraries for KERI Key Event Log events.
 *
 * Generates structurally valid events that maintain internal consistency:
 * - sn starts at 0, increments by 1
 * - p (prior digest) chains correctly
 * - d (SAID) is computed from the content
 * - k/n lists have correct lengths
 */

import fc from 'fast-check';
import { arbKeyList, arbDigestList, arbSimpleThreshold, arbWitnessList } from './keys.js';
import { computeEventSaids } from '../util/said.js';

/**
 * KERI event field ordering per the spec.
 * Events MUST serialize fields in this order.
 */
export const ICP_FIELD_ORDER = ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'] as const;
export const ROT_FIELD_ORDER = ['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'br', 'ba', 'c', 'a'] as const;
export const IXN_FIELD_ORDER = ['v', 't', 'd', 'i', 's', 'p', 'a'] as const;

/** Minimal inception event (no witnesses, no delegation). */
export const arbInceptionEvent: fc.Arbitrary<Record<string, unknown>> = fc
  .tuple(
    arbKeyList(1, 3),
    arbDigestList(1, 3),
  )
  .chain(([keys, digests]) =>
    fc.tuple(
      arbSimpleThreshold(keys.length),
      arbSimpleThreshold(digests.length),
    ).map(([kt, nt]) => {
      const raw: Record<string, unknown> = {
        v: 'KERI10JSON000000_',
        t: 'icp',
        d: '',
        i: '',
        s: '0',
        kt,
        k: keys,
        nt,
        n: digests,
        bt: '0',
        b: [],
        c: [],
        a: [],
      };
      return computeEventSaids(raw, 'E') as Record<string, unknown>;
    }),
  );

/** Inception event with witnesses. */
export const arbInceptionWithWitnesses: fc.Arbitrary<Record<string, unknown>> = fc
  .tuple(
    arbKeyList(1, 3),
    arbDigestList(1, 3),
    arbWitnessList(1, 3),
  )
  .chain(([keys, digests, witnesses]) =>
    fc.tuple(
      arbSimpleThreshold(keys.length),
      arbSimpleThreshold(digests.length),
      fc.integer({ min: 1, max: witnesses.length }),
    ).map(([kt, nt, toad]) => {
      const raw: Record<string, unknown> = {
        v: 'KERI10JSON000000_',
        t: 'icp',
        d: '',
        i: '',
        s: '0',
        kt,
        k: keys,
        nt,
        n: digests,
        bt: toad.toString(16),
        b: witnesses,
        c: [],
        a: [],
      };
      return computeEventSaids(raw, 'E') as Record<string, unknown>;
    }),
  );

/**
 * Generate a rotation event that correctly chains from a prior event.
 */
export function arbRotationFrom(prior: {
  said: string;
  prefix: string;
  sn: number;
}): fc.Arbitrary<Record<string, unknown>> {
  return fc
    .tuple(arbKeyList(1, 3), arbDigestList(1, 3))
    .chain(([keys, digests]) =>
      fc.tuple(
        arbSimpleThreshold(keys.length),
        arbSimpleThreshold(digests.length),
      ).map(([kt, nt]) => {
        const raw: Record<string, unknown> = {
          v: 'KERI10JSON000000_',
          t: 'rot',
          d: '',
          i: prior.prefix,
          s: (prior.sn + 1).toString(16),
          p: prior.said,
          kt,
          k: keys,
          nt,
          n: digests,
          bt: '0',
          br: [],
          ba: [],
          c: [],
          a: [],
        };
        return computeEventSaids(raw, 'E') as Record<string, unknown>;
      }),
    );
}

/**
 * Generate an interaction event that correctly chains from a prior event.
 */
export function arbInteractionFrom(prior: {
  said: string;
  prefix: string;
  sn: number;
}): fc.Arbitrary<Record<string, unknown>> {
  return fc.constant(null).map(() => {
    const raw: Record<string, unknown> = {
      v: 'KERI10JSON000000_',
      t: 'ixn',
      d: '',
      i: prior.prefix,
      s: (prior.sn + 1).toString(16),
      p: prior.said,
      a: [],
    };
    return computeEventSaids(raw, 'E') as Record<string, unknown>;
  });
}

/**
 * Generate a complete KEL: inception + N subsequent events.
 * Each event correctly chains to the prior.
 */
export function arbKelSequence(
  minSubsequent: number = 0,
  maxSubsequent: number = 5,
): fc.Arbitrary<Record<string, unknown>[]> {
  return arbInceptionEvent.chain(icp => {
    return fc
      .array(fc.boolean(), { minLength: minSubsequent, maxLength: maxSubsequent })
      .chain(isRotations => {
        // Build the KEL step by step
        let current = {
          said: icp['d'] as string,
          prefix: icp['i'] as string,
          sn: 0,
        };

        // We need to build this imperatively since each event depends on the prior
        const events: Record<string, unknown>[] = [icp];

        // Generate arbitrary for each subsequent event
        if (isRotations.length === 0) return fc.constant(events);

        return isRotations.reduce(
          (chain: fc.Arbitrary<Record<string, unknown>[]>, isRot, _idx) => {
            return chain.chain(evts => {
              const last = evts[evts.length - 1];
              const prior = {
                said: last['d'] as string,
                prefix: last['i'] as string,
                sn: typeof last['s'] === 'string'
                  ? parseInt(last['s'] as string, 16)
                  : 0,
              };

              const nextEvent = isRot
                ? arbRotationFrom(prior)
                : arbInteractionFrom(prior);

              return nextEvent.map(evt => [...evts, evt]);
            });
          },
          fc.constant(events),
        );
      });
  });
}
