/**
 * SAID (Self-Addressing Identifier) Invariants:
 *
 * Property 1: For any JSON object and digest code,
 *   computeSaid(obj, field, code) produces a deterministic result.
 *   Calling it twice with the same input yields the same SAID.
 *
 * Property 2: verifySaid returns true for a correctly SAIDified object.
 *
 * Property 3: Flipping any bit in the content invalidates the SAID.
 *
 * Property 4: For KERI inception events, d == i (both are the SAID).
 */

import fc from 'fast-check';
import { computeSaid, verifySaid, computeEventSaids } from '../util/said.js';
import { CODE_TABLE } from '../util/cesr-codec.js';

/** Generate a simple JSON object with string values. */
const arbJsonObj = fc.dictionary(
  fc.string({ minLength: 1, maxLength: 8 }).filter(s => s !== 'd' && s !== 'i'),
  fc.oneof(fc.string(), fc.integer(), fc.boolean()),
  { minKeys: 1, maxKeys: 10 },
);

/** Digest codes that support SAID computation. */
const SAID_CODES = ['E', 'F', 'G', 'H'] as const;
const arbSaidCode = fc.constantFrom(...SAID_CODES);

/** Property: SAID computation is deterministic. */
export const saidDeterministic = fc.property(
  arbJsonObj,
  arbSaidCode,
  (obj, code) => {
    const withD = { d: '', ...obj };
    const said1 = computeSaid(withD, 'd', code);
    const said2 = computeSaid(withD, 'd', code);
    return said1 === said2;
  },
);

/** Property: computeSaid followed by verifySaid returns true. */
export const saidComputeVerify = fc.property(
  arbJsonObj,
  arbSaidCode,
  (obj, code) => {
    const withD = { d: '', ...obj };
    const said = computeSaid(withD, 'd', code);
    const saidified = { ...withD, d: said };
    return verifySaid(saidified, 'd');
  },
);

/** Property: SAID has correct length for its code. */
export const saidLength = fc.property(
  arbJsonObj,
  arbSaidCode,
  (obj, code) => {
    const withD = { d: '', ...obj };
    const said = computeSaid(withD, 'd', code);
    return said.length === CODE_TABLE[code].fs;
  },
);

/** Property: SAID starts with its derivation code. */
export const saidStartsWithCode = fc.property(
  arbJsonObj,
  arbSaidCode,
  (obj, code) => {
    const withD = { d: '', ...obj };
    const said = computeSaid(withD, 'd', code);
    return said.startsWith(code);
  },
);

/**
 * Property: modifying any value in the object invalidates the SAID.
 * We mutate one key's value and verify the SAID no longer matches.
 */
export const saidSensitiveToChanges = fc.property(
  arbJsonObj,
  arbSaidCode,
  fc.string({ minLength: 1 }),
  (obj, code, newVal) => {
    const withD = { d: '', ...obj };
    const said = computeSaid(withD, 'd', code);
    const saidified = { ...withD, d: said };

    // Pick a non-'d' key and change it
    const keys = Object.keys(saidified).filter(k => k !== 'd');
    if (keys.length === 0) return true; // no keys to mutate

    const mutated = { ...saidified, [keys[0]]: newVal + '_mutated' };
    return !verifySaid(mutated, 'd');
  },
);

/**
 * Property: For inception events, d == i after SAIDification.
 */
export const inceptionSaidEquality = fc.property(
  arbSaidCode,
  (code) => {
    const event: Record<string, unknown> = {
      v: 'KERI10JSON000000_',
      t: 'icp',
      d: '',
      i: '',
      s: '0',
      kt: '1',
      k: ['DAbcdefghijklmnopqrstuvwxyz012345678901234'],
      nt: '1',
      n: ['EAbcdefghijklmnopqrstuvwxyz012345678901234'],
      bt: '0',
      b: [],
      c: [],
      a: [],
    };

    const result = computeEventSaids(event, code);
    return result['d'] === result['i'] && typeof result['d'] === 'string' && (result['d'] as string).length > 0;
  },
);
