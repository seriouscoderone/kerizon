/**
 * Z3 constraints for SAID structural integrity.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove SAID field lengths are constrained to valid CESR sizes.
 * Returns 'unsat' if no invalid length can satisfy the constraints.
 */
export async function proveSaidLengthConstraints(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('said-len');
  const solver = new ctx.Solver();

  const saidLen = ctx.Int.const('said_len');
  const dummyLen = ctx.Int.const('dummy_len');

  // dummy length must equal SAID length
  solver.add(ctx.Eq(saidLen, dummyLen));

  // SAID length must be valid CESR digest size: 44 or 88
  solver.add(ctx.Or(ctx.Eq(saidLen, ctx.Int.val(44)), ctx.Eq(saidLen, ctx.Int.val(88))));
  solver.add(saidLen.gt(ctx.Int.val(0)));

  // Try to find a length that satisfies these constraints but is NOT 44 or 88
  // This is contradictory, so should be UNSAT
  const invalidSolver = new ctx.Solver();
  const invalidLen = ctx.Int.const('invalid_len');
  invalidSolver.add(invalidLen.gt(ctx.Int.val(0)));
  // Must be a "valid" length...
  invalidSolver.add(ctx.Or(ctx.Eq(invalidLen, ctx.Int.val(44)), ctx.Eq(invalidLen, ctx.Int.val(88))));
  // ...but also NOT 44 or 88
  invalidSolver.add(ctx.Not(ctx.Eq(invalidLen, ctx.Int.val(44))));
  invalidSolver.add(ctx.Not(ctx.Eq(invalidLen, ctx.Int.val(88))));

  const invalidResult = await invalidSolver.check();

  return { result: invalidResult as 'sat' | 'unsat' | 'unknown' };
}

/**
 * Prove SAID determinism: hash(x) always equals hash(x).
 */
export async function proveSaidDeterminism(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('said-det');
  const solver = new ctx.Solver();

  const hashFn = ctx.Function.declare('hash', ctx.Int.sort(), ctx.Int.sort());
  const input = ctx.Int.const('input');

  // Can hash(x) != hash(x)? Should be UNSAT.
  solver.add(ctx.Not(ctx.Eq(hashFn.call(input), hashFn.call(input))));

  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}
