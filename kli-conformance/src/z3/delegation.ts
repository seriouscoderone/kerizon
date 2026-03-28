/**
 * Z3 constraints for delegation chain validity.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove delegation requires both directions of the peg.
 * valid_delegation ↔ (di_matches ∧ seal_exists)
 */
export async function proveBidirectionalPeg(): Promise<{
  bothDirectionsRequired: boolean;
  details: {
    neitherDirection: 'sat' | 'unsat' | 'unknown';
    onlyDi: 'sat' | 'unsat' | 'unknown';
    onlySeal: 'sat' | 'unsat' | 'unknown';
    bothDirections: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('del');

  const diMatches = ctx.Bool.const('di_matches');
  const sealExists = ctx.Bool.const('seal_exists');
  const validDelegation = ctx.Bool.const('valid_delegation');

  const definition = ctx.Eq(validDelegation, ctx.And(diMatches, sealExists));

  // Test 1: neither → should be UNSAT for valid
  const s1 = new ctx.Solver();
  s1.add(definition);
  s1.add(ctx.Not(diMatches), ctx.Not(sealExists), validDelegation);
  const r1 = await s1.check();

  // Test 2: only di → UNSAT
  const s2 = new ctx.Solver();
  s2.add(definition);
  s2.add(diMatches, ctx.Not(sealExists), validDelegation);
  const r2 = await s2.check();

  // Test 3: only seal → UNSAT
  const s3 = new ctx.Solver();
  s3.add(definition);
  s3.add(ctx.Not(diMatches), sealExists, validDelegation);
  const r3 = await s3.check();

  // Test 4: both → SAT
  const s4 = new ctx.Solver();
  s4.add(definition);
  s4.add(diMatches, sealExists, validDelegation);
  const r4 = await s4.check();

  return {
    bothDirectionsRequired: r1 === 'unsat' && r2 === 'unsat' && r3 === 'unsat' && r4 === 'sat',
    details: {
      neitherDirection: r1 as 'sat' | 'unsat' | 'unknown',
      onlyDi: r2 as 'sat' | 'unsat' | 'unknown',
      onlySeal: r3 as 'sat' | 'unsat' | 'unknown',
      bothDirections: r4 as 'sat' | 'unsat' | 'unknown',
    },
  };
}

/**
 * Prove delegation seal must exactly match all three fields (i, s, d).
 */
export async function proveSealExactMatch(): Promise<{
  allFieldsRequired: boolean;
  details: {
    allMatch: 'sat' | 'unsat' | 'unknown';
    prefixMismatch: 'sat' | 'unsat' | 'unknown';
    snMismatch: 'sat' | 'unsat' | 'unknown';
    saidMismatch: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('seal');

  const sealI = ctx.Int.const('seal_i');
  const sealS = ctx.Int.const('seal_s');
  const sealD = ctx.Int.const('seal_d');
  const eventI = ctx.Int.const('event_i');
  const eventS = ctx.Int.const('event_s');
  const eventD = ctx.Int.const('event_d');

  const validSeal = ctx.Bool.const('valid_seal');
  const definition = ctx.Eq(
    validSeal,
    ctx.And(ctx.Eq(sealI, eventI), ctx.Eq(sealS, eventS), ctx.Eq(sealD, eventD)),
  );

  const distinct = ctx.And(
    ctx.Not(ctx.Eq(eventI, eventS)),
    ctx.Not(ctx.Eq(eventS, eventD)),
    ctx.Not(ctx.Eq(eventI, eventD)),
  );

  // All match → SAT
  const s1 = new ctx.Solver();
  s1.add(definition, distinct);
  s1.add(ctx.Eq(sealI, eventI), ctx.Eq(sealS, eventS), ctx.Eq(sealD, eventD), validSeal);
  const r1 = await s1.check();

  // Prefix mismatch → UNSAT
  const s2 = new ctx.Solver();
  s2.add(definition, distinct);
  s2.add(ctx.Not(ctx.Eq(sealI, eventI)), validSeal);
  const r2 = await s2.check();

  // sn mismatch → UNSAT
  const s3 = new ctx.Solver();
  s3.add(definition, distinct);
  s3.add(ctx.Not(ctx.Eq(sealS, eventS)), validSeal);
  const r3 = await s3.check();

  // SAID mismatch → UNSAT
  const s4 = new ctx.Solver();
  s4.add(definition, distinct);
  s4.add(ctx.Not(ctx.Eq(sealD, eventD)), validSeal);
  const r4 = await s4.check();

  return {
    allFieldsRequired: r1 === 'sat' && r2 === 'unsat' && r3 === 'unsat' && r4 === 'unsat',
    details: {
      allMatch: r1 as 'sat' | 'unsat' | 'unknown',
      prefixMismatch: r2 as 'sat' | 'unsat' | 'unknown',
      snMismatch: r3 as 'sat' | 'unsat' | 'unknown',
      saidMismatch: r4 as 'sat' | 'unsat' | 'unknown',
    },
  };
}
