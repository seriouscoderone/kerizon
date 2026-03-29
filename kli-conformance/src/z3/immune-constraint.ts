/**
 * Z3 constraints for KAWA witness immune constraint and quorum intersection.
 *
 * The immune constraint (2*M >= N + F + 1) ensures that any two quorum-
 * sized witness subsets overlap, preventing equivocation even under F
 * Byzantine faults. The ample() formula computes the minimum threshold
 * that satisfies this constraint.
 *
 * See KERI spec section on KAWA (KERI Agreement Algorithm for Watchers).
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove the immune constraint: 2*M >= N + F + 1.
 * When this holds, any two quorum-sized subsets of witnesses must intersect,
 * preventing equivocation.
 *
 * Returns 'unsat' when there is NO way to violate quorum intersection
 * under the immune constraint (i.e., the constraint is sound).
 */
export async function proveImmuneConstraint(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  details: {
    immuneHoldsButNoIntersection: 'sat' | 'unsat' | 'unknown';
    immuneViolatedAllowsDisjoint: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('immune');

  const N = ctx.Int.const('N'); // total witnesses
  const F = ctx.Int.const('F'); // faulty witnesses
  const M = ctx.Int.const('M'); // accountability threshold

  // Shared domain constraints
  const domain = [
    N.gt(ctx.Int.val(0)),
    F.ge(ctx.Int.val(0)),
    F.lt(N),
    M.gt(ctx.Int.val(0)),
    M.le(N),
  ];

  // Immune constraint: 2*M >= N + F + 1  (equivalent to M >= ceil((N+F+1)/2))
  const immuneHolds = ctx.Int.val(2).mul(M).ge(N.add(F).add(ctx.Int.val(1)));

  // Quorum intersection property: two subsets of size >= M from N
  // must intersect. By pigeonhole, |A| + |B| > N implies |A n B| >= 1.
  // Honest witnesses >= N - F, so we need M > N - (N - F) = F is not
  // sufficient alone. Full argument: if two quorums each have M members,
  // their union is at most N, so |A n B| >= 2*M - N.
  // We want 2*M - N >= 1, i.e. 2*M > N.
  // Under immune: 2*M > N + F + 1 > N (since F >= 0), so intersection holds.

  // Test 1: Can immune hold but quorum intersection fail?
  // Intersection size = 2*M - N; fail means 2*M - N < 1, i.e. 2*M <= N
  const s1 = new ctx.Solver();
  s1.add(...domain);
  s1.add(immuneHolds);
  s1.add(ctx.Int.val(2).mul(M).le(N)); // no intersection
  const r1 = await s1.check();

  // Test 2: Can immune be violated and disjoint quorums exist?
  const s2 = new ctx.Solver();
  s2.add(...domain);
  s2.add(ctx.Not(immuneHolds));
  s2.add(ctx.Int.val(2).mul(M).le(N));
  const r2 = await s2.check();

  return {
    result: r1 as 'sat' | 'unsat' | 'unknown',
    details: {
      immuneHoldsButNoIntersection: r1 as 'sat' | 'unsat' | 'unknown',
      immuneViolatedAllowsDisjoint: r2 as 'sat' | 'unsat' | 'unknown',
    },
  };
}

/**
 * Compute the ample() formula threshold and verify it satisfies the immune
 * constraint for witness counts 1..maxN.
 *
 * ample(n) = ceil((n + 1 + floor((n-1)/3)) / 2)
 *
 * For each n, prove that ample(n) satisfies 2*M >= N + F + 1 where
 * F = floor((n-1)/3) (maximum tolerable faults for BFT).
 */
export async function proveAmpleFormula(maxN: number): Promise<{
  allSatisfied: boolean;
  results: Array<{
    n: number;
    ampleValue: number;
    f: number;
    immuneSatisfied: boolean;
  }>;
}> {
  const results: Array<{
    n: number;
    ampleValue: number;
    f: number;
    immuneSatisfied: boolean;
  }> = [];

  const { Context } = await getZ3();

  for (let n = 1; n <= maxN; n++) {
    const f = Math.floor((n - 1) / 3);
    const ampleVal = Math.ceil((n + 1 + f) / 2);

    const ctx = new Context(`ample_${n}`);
    const solver = new ctx.Solver();

    const N = ctx.Int.const('N');
    const F = ctx.Int.const('F');
    const M = ctx.Int.const('M');

    // Fix values
    solver.add(ctx.Eq(N, ctx.Int.val(n)));
    solver.add(ctx.Eq(F, ctx.Int.val(f)));
    solver.add(ctx.Eq(M, ctx.Int.val(ampleVal)));

    // Assert immune constraint is VIOLATED: 2*M < N + F + 1
    solver.add(ctx.Int.val(2).mul(M).lt(N.add(F).add(ctx.Int.val(1))));

    const result = await solver.check();
    // If UNSAT, the immune constraint holds (cannot be violated)
    results.push({
      n,
      ampleValue: ampleVal,
      f,
      immuneSatisfied: result === 'unsat',
    });
  }

  return {
    allSatisfied: results.every(r => r.immuneSatisfied),
    results,
  };
}

/**
 * Prove quorum intersection: for any two subsets of size >= M from a set
 * of size N, their intersection is >= 1 when M > N/2.
 *
 * Models this via inclusion-exclusion: |A u B| <= N, |A|>=M, |B|>=M,
 * |A n B| = |A| + |B| - |A u B| >= 2*M - N.
 * If 2*M > N, then |A n B| >= 1.
 */
export async function proveQuorumIntersection(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  details: {
    majorityImpliesIntersection: 'sat' | 'unsat' | 'unknown';
    nonMajorityAllowsDisjoint: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('quorum');

  const N = ctx.Int.const('N');
  const M = ctx.Int.const('M');
  const sizeA = ctx.Int.const('sizeA');
  const sizeB = ctx.Int.const('sizeB');
  const unionAB = ctx.Int.const('unionAB');
  const interAB = ctx.Int.const('interAB');

  const domain = [
    N.gt(ctx.Int.val(0)),
    M.gt(ctx.Int.val(0)),
    M.le(N),
    sizeA.ge(M),
    sizeA.le(N),
    sizeB.ge(M),
    sizeB.le(N),
    unionAB.le(N),
    unionAB.ge(sizeA),
    unionAB.ge(sizeB),
    // inclusion-exclusion
    ctx.Eq(interAB, sizeA.add(sizeB).sub(unionAB)),
    interAB.ge(ctx.Int.val(0)),
  ];

  // Test 1: M > N/2 (2*M > N) but intersection < 1? Should be UNSAT.
  const s1 = new ctx.Solver();
  s1.add(...domain);
  s1.add(ctx.Int.val(2).mul(M).gt(N));
  s1.add(interAB.lt(ctx.Int.val(1)));
  const r1 = await s1.check();

  // Test 2: M <= N/2 allows disjoint? Should be SAT.
  const s2 = new ctx.Solver();
  s2.add(...domain);
  s2.add(ctx.Int.val(2).mul(M).le(N));
  s2.add(ctx.Eq(interAB, ctx.Int.val(0)));
  const r2 = await s2.check();

  return {
    result: r1 as 'sat' | 'unsat' | 'unknown',
    details: {
      majorityImpliesIntersection: r1 as 'sat' | 'unsat' | 'unknown',
      nonMajorityAllowsDisjoint: r2 as 'sat' | 'unsat' | 'unknown',
    },
  };
}
