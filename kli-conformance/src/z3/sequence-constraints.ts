/**
 * Z3 constraints for sequence number monotonicity.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove sn constraints admit exactly one valid assignment.
 * For a KEL of length N, sn[i] must equal i for all i.
 */
export async function proveSequenceUniqueness(kelLength: number): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  model?: Record<string, number>;
}> {
  const { Context } = await getZ3();
  const ctx = new Context('seq');
  const solver = new ctx.Solver();

  const sns = Array.from({ length: kelLength }, (_, i) =>
    ctx.Int.const(`sn_${i}`),
  );

  // sn[0] == 0
  solver.add(ctx.Eq(sns[0], ctx.Int.val(0)));

  // sn[i] == sn[i-1] + 1
  for (let i = 1; i < kelLength; i++) {
    solver.add(ctx.Eq(sns[i], sns[i - 1].add(ctx.Int.val(1))));
  }

  // all non-negative
  for (const sn of sns) {
    solver.add(sn.ge(ctx.Int.val(0)));
  }

  // Ask: can any sn[i] != i? (should be UNSAT)
  const violationClauses = sns.map((sn, i) =>
    ctx.Not(ctx.Eq(sn, ctx.Int.val(i))),
  );
  solver.add(ctx.Or(...violationClauses));

  const result = await solver.check();

  let model: Record<string, number> | undefined;
  if (result === 'sat') {
    const m = solver.model();
    model = {};
    for (let i = 0; i < kelLength; i++) {
      model[`sn_${i}`] = Number(m.eval(sns[i]).toString());
    }
  }

  return { result: result as 'sat' | 'unsat' | 'unknown', model };
}

/**
 * Prove gaps ARE possible under relaxed monotonicity,
 * proving our strict +1 constraint is necessary.
 */
export async function proveGapDetection(kelLength: number): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('gap');
  const solver = new ctx.Solver();

  const sns = Array.from({ length: kelLength }, (_, i) =>
    ctx.Int.const(`sn_${i}`),
  );

  solver.add(ctx.Eq(sns[0], ctx.Int.val(0)));
  for (const sn of sns) solver.add(sn.ge(ctx.Int.val(0)));

  // Relaxed: sn[i] > sn[i-1] (not necessarily +1)
  for (let i = 1; i < kelLength; i++) {
    solver.add(sns[i].gt(sns[i - 1]));
  }

  // Require at least one gap
  const gapClauses = [];
  for (let i = 1; i < kelLength; i++) {
    gapClauses.push(ctx.Not(ctx.Eq(sns[i], sns[i - 1].add(ctx.Int.val(1)))));
  }
  solver.add(ctx.Or(...gapClauses));

  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}
