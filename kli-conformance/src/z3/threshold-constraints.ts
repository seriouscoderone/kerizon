/**
 * Z3 constraints for signing and witness threshold satisfaction.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove simple threshold satisfaction.
 * Given N signers and threshold M, is there a subset of size >= M?
 */
export async function proveSimpleThreshold(
  signerCount: number,
  threshold: number,
): Promise<{ result: 'sat' | 'unsat' | 'unknown'; satisfyingSet?: boolean[] }> {
  const { Context } = await getZ3();
  const ctx = new Context('thresh');
  const solver = new ctx.Solver();

  const signed = Array.from({ length: signerCount }, (_, i) =>
    ctx.Bool.const(`signed_${i}`),
  );

  // Count how many signed
  let sum: any = ctx.Int.val(0);
  for (const s of signed) {
    sum = sum.add(ctx.If(s, ctx.Int.val(1), ctx.Int.val(0)));
  }

  solver.add(sum.ge(ctx.Int.val(threshold)));

  const result = await solver.check();
  let satisfyingSet: boolean[] | undefined;
  if (result === 'sat') {
    const m = solver.model();
    satisfyingSet = signed.map(s => m.eval(s).toString() === 'true');
  }

  return { result: result as 'sat' | 'unsat' | 'unknown', satisfyingSet };
}

/**
 * Alias: prove a threshold cannot be satisfied.
 */
export async function proveThresholdImpossible(
  signerCount: number,
  threshold: number,
): Promise<{ result: 'sat' | 'unsat' | 'unknown' }> {
  return proveSimpleThreshold(signerCount, threshold);
}

/**
 * Model fractionally weighted threshold.
 * Each clause has rational weights per key. Clause satisfied when sum >= 1.
 * ALL clauses must be satisfied.
 */
export async function proveFractionalThreshold(
  clauses: Array<Array<[number, number]>>,
): Promise<{ result: 'sat' | 'unsat' | 'unknown'; satisfyingSet?: boolean[] }> {
  if (clauses.length === 0) return { result: 'sat', satisfyingSet: [] };

  const keyCount = clauses[0].length;
  const { Context } = await getZ3();
  const ctx = new Context('frac');
  const solver = new ctx.Solver();

  const verified = Array.from({ length: keyCount }, (_, i) =>
    ctx.Bool.const(`key_${i}`),
  );

  for (const clause of clauses) {
    // Build weighted sum using Real division
    let weightedSum: any = ctx.Real.val(0);
    for (let k = 0; k < keyCount; k++) {
      const [num, den] = clause[k];
      const weight = ctx.Real.val(num).div(ctx.Real.val(den));
      const contribution = ctx.If(verified[k], weight, ctx.Real.val(0));
      weightedSum = weightedSum.add(contribution);
    }
    solver.add(weightedSum.ge(ctx.Real.val(1)));
  }

  const result = await solver.check();
  let satisfyingSet: boolean[] | undefined;
  if (result === 'sat') {
    const m = solver.model();
    satisfyingSet = verified.map(v => m.eval(v).toString() === 'true');
  }

  return { result: result as 'sat' | 'unsat' | 'unknown', satisfyingSet };
}

/**
 * Prove witness tally constraint.
 */
export async function proveWitnessTally(
  witnessCount: number,
  toad: number,
): Promise<{ result: 'sat' | 'unsat' | 'unknown' }> {
  return proveSimpleThreshold(witnessCount, toad);
}
