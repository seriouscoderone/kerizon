/**
 * Z3 constraints for pre-rotation key commitment.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove pre-rotation commitment is binding.
 * With an injective hash, two different key sets cannot both match the same digests.
 */
export async function proveCommitmentBinding(keyCount: number): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('kc');
  const solver = new ctx.Solver();

  const hashFn = ctx.Function.declare('hash', ctx.BitVec.sort(256), ctx.BitVec.sort(256));

  const keysA = Array.from({ length: keyCount }, (_, i) => ctx.BitVec.const(`keyA_${i}`, 256));
  const keysB = Array.from({ length: keyCount }, (_, i) => ctx.BitVec.const(`keyB_${i}`, 256));
  const digests = Array.from({ length: keyCount }, (_, i) => ctx.BitVec.const(`digest_${i}`, 256));

  // Both sets hash to the same digests
  for (let i = 0; i < keyCount; i++) {
    solver.add(ctx.Eq(hashFn.call(keysA[i]), digests[i]));
    solver.add(ctx.Eq(hashFn.call(keysB[i]), digests[i]));
  }

  // Hash is injective: h(a) == h(b) → a == b
  for (let i = 0; i < keyCount; i++) {
    solver.add(ctx.Implies(
      ctx.Eq(hashFn.call(keysA[i]), hashFn.call(keysB[i])),
      ctx.Eq(keysA[i], keysB[i]),
    ));
  }

  // Ask: can keysA differ from keysB? Should be UNSAT.
  const differClauses = keysA.map((kA, i) => ctx.Not(ctx.Eq(kA, keysB[i])));
  solver.add(ctx.Or(...differClauses));

  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}

/**
 * Prove revealed keys cannot exceed committed digests.
 */
export async function proveKeyCountConstraint(
  committedCount: number,
  revealedCount: number,
): Promise<{ result: 'sat' | 'unsat' | 'unknown' }> {
  const { Context } = await getZ3();
  const ctx = new Context('kcc');
  const solver = new ctx.Solver();

  const committed = ctx.Int.const('committed');
  const revealed = ctx.Int.const('revealed');

  solver.add(ctx.Eq(committed, ctx.Int.val(committedCount)));
  solver.add(ctx.Eq(revealed, ctx.Int.val(revealedCount)));

  // Violation: revealed > committed
  solver.add(revealed.gt(committed));

  // SAT if revealedCount > committedCount (violation found), UNSAT otherwise
  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}
