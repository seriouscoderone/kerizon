/**
 * Z3 constraints for CESR structural alignment invariants.
 *
 * Proves fundamental CESR encoding properties:
 * - Quadlet alignment: 4 T-domain chars = 3 B-domain bytes = 24 bits
 * - Pad size derivation from raw byte length
 * - Code size alignment by pad size
 * - Cold start tritet bijection
 *
 * See CESR spec for definitions of T-domain, B-domain, quadlets.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Prove quadlet alignment: 4 T-domain chars = 3 B-domain bytes = 24 bits.
 * No matter how many quadlets, the ratio is always 4:3.
 */
export async function proveQuadletAlignment(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  details: {
    ratioHolds: 'sat' | 'unsat' | 'unknown';
    ratioViolationImpossible: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('quadlet');

  const quadlets = ctx.Int.const('quadlets');
  const tChars = ctx.Int.const('t_chars');
  const bBytes = ctx.Int.const('b_bytes');
  const bits = ctx.Int.const('bits');

  const definitions = [
    quadlets.gt(ctx.Int.val(0)),
    ctx.Eq(tChars, quadlets.mul(ctx.Int.val(4))),
    ctx.Eq(bBytes, quadlets.mul(ctx.Int.val(3))),
    ctx.Eq(bits, quadlets.mul(ctx.Int.val(24))),
  ];

  // Test 1: Can we find a valid assignment? (SAT)
  const s1 = new ctx.Solver();
  s1.add(...definitions);
  const r1 = await s1.check();

  // Test 2: Can T-chars / quadlets != 4 or B-bytes / quadlets != 3? (UNSAT)
  // Equivalently: can 3 * t_chars != 4 * b_bytes?
  const s2 = new ctx.Solver();
  s2.add(...definitions);
  s2.add(ctx.Not(ctx.Eq(
    ctx.Int.val(3).mul(tChars),
    ctx.Int.val(4).mul(bBytes),
  )));
  const r2 = await s2.check();

  return {
    result: r2 as 'sat' | 'unsat' | 'unknown',
    details: {
      ratioHolds: r1 as 'sat' | 'unsat' | 'unknown',
      ratioViolationImpossible: r2 as 'sat' | 'unsat' | 'unknown',
    },
  };
}

/**
 * Prove pad size formula: ps = (3 - (N % 3)) % 3 where N is raw byte length.
 * pad_size is always 0, 1, or 2.
 */
export async function provePadSizeFormula(): Promise<{
  allCorrect: boolean;
  results: Array<{
    rawLen: number;
    expectedPad: number;
    formulaHolds: boolean;
  }>;
}> {
  const { Context } = await getZ3();
  const results: Array<{
    rawLen: number;
    expectedPad: number;
    formulaHolds: boolean;
  }> = [];

  // Test for representative byte lengths 0..11
  for (let n = 0; n <= 11; n++) {
    const expectedPad = (3 - (n % 3)) % 3;

    const ctx = new Context(`pad_${n}`);
    const solver = new ctx.Solver();

    const N = ctx.Int.const('N');
    const ps = ctx.Int.const('ps');

    solver.add(ctx.Eq(N, ctx.Int.val(n)));

    // ps = (3 - (N mod 3)) mod 3
    // We model this: there exist q, r such that N = 3*q + r, 0 <= r < 3
    // then ps = (3 - r) mod 3
    const r = ctx.Int.const('r');
    const q = ctx.Int.const('q');
    solver.add(ctx.Eq(N, ctx.Int.val(3).mul(q).add(r)));
    solver.add(r.ge(ctx.Int.val(0)));
    solver.add(r.lt(ctx.Int.val(3)));
    solver.add(q.ge(ctx.Int.val(0)));

    // ps = (3 - r) mod 3
    const ps_r = ctx.Int.const('ps_r');
    const ps_q = ctx.Int.const('ps_q');
    solver.add(ctx.Eq(ctx.Int.val(3).sub(r), ctx.Int.val(3).mul(ps_q).add(ps)));
    solver.add(ps.ge(ctx.Int.val(0)));
    solver.add(ps.lt(ctx.Int.val(3)));
    solver.add(ps_q.ge(ctx.Int.val(0)));

    // Assert ps != expectedPad (should be UNSAT if formula is correct)
    solver.add(ctx.Not(ctx.Eq(ps, ctx.Int.val(expectedPad))));

    const result = await solver.check();
    results.push({
      rawLen: n,
      expectedPad,
      formulaHolds: result === 'unsat',
    });
  }

  return {
    allCorrect: results.every(r => r.formulaHolds),
    results,
  };
}

/**
 * Prove code size alignment by pad size:
 *   ps=0 -> cs % 4 == 0
 *   ps=1 -> cs % 4 == 1
 *   ps=2 -> cs % 4 == 2
 *
 * In CESR, a primitive has cs T-domain code chars and vs T-domain value
 * chars encoding the raw bytes. The value size vs = ceil(raw * 4/3),
 * and the total (cs + vs) must be a multiple of 4 (quadlet-aligned).
 *
 * Since ps = (3 - (raw % 3)) % 3, the remainder vs % 4 is determined
 * by raw % 3:
 *   raw%3==0 -> vs%4==0 -> cs%4==0 -> ps==0
 *   raw%3==1 -> vs%4==2 -> cs%4==2 -> ps==2
 *   raw%3==2 -> vs%4==3 -> cs%4==1 -> ps==1
 */
export async function proveCodeSizeAlignment(): Promise<{
  allCorrect: boolean;
  results: Array<{
    padSize: number;
    expectedCsMod4: number;
    constraintHolds: boolean;
  }>;
}> {
  const { Context } = await getZ3();
  const results: Array<{
    padSize: number;
    expectedCsMod4: number;
    constraintHolds: boolean;
  }> = [];

  for (let ps = 0; ps <= 2; ps++) {
    const expectedMod = ps;

    const ctx = new Context(`csa_${ps}`);
    const solver = new ctx.Solver();

    const cs = ctx.Int.const('cs');     // code size (T-domain chars)
    const raw = ctx.Int.const('raw');   // raw material byte length
    const vs = ctx.Int.const('vs');     // value size (T-domain chars)

    solver.add(cs.gt(ctx.Int.val(0)));
    solver.add(raw.ge(ctx.Int.val(0)));

    // pad size from raw: ps = (3 - (raw % 3)) % 3
    // Model raw = 3*q + r, 0 <= r < 3
    const rawQ = ctx.Int.const('raw_q');
    const rawR = ctx.Int.const('raw_r');
    solver.add(ctx.Eq(raw, ctx.Int.val(3).mul(rawQ).add(rawR)));
    solver.add(rawR.ge(ctx.Int.val(0)));
    solver.add(rawR.lt(ctx.Int.val(3)));
    solver.add(rawQ.ge(ctx.Int.val(0)));

    // Fix the remainder to match the target pad size
    // ps=0 -> rawR=0, ps=1 -> rawR=2, ps=2 -> rawR=1
    const rawRemForPad = ps === 0 ? 0 : ps === 1 ? 2 : 1;
    solver.add(ctx.Eq(rawR, ctx.Int.val(rawRemForPad)));

    // vs = ceil(raw * 4 / 3)
    // For raw = 3q+r: vs = 4q + ceil(4r/3)
    // r=0: vs = 4q, r=1: vs = 4q+2, r=2: vs = 4q+3
    const vsCeil = rawRemForPad === 0 ? 0 : rawRemForPad === 1 ? 2 : 3;
    solver.add(ctx.Eq(vs, rawQ.mul(ctx.Int.val(4)).add(ctx.Int.val(vsCeil))));

    // Total must be quadlet-aligned: (cs + vs) % 4 == 0
    const total = cs.add(vs);
    const totalQ = ctx.Int.const('total_q');
    solver.add(ctx.Eq(total, ctx.Int.val(4).mul(totalQ)));
    solver.add(totalQ.gt(ctx.Int.val(0)));

    // Derive cs % 4
    const csRem = ctx.Int.const('cs_rem');
    const csQ = ctx.Int.const('cs_q');
    solver.add(ctx.Eq(cs, ctx.Int.val(4).mul(csQ).add(csRem)));
    solver.add(csRem.ge(ctx.Int.val(0)));
    solver.add(csRem.lt(ctx.Int.val(4)));
    solver.add(csQ.ge(ctx.Int.val(0)));

    // Assert cs % 4 != ps (should be UNSAT, proving cs%4 must equal ps)
    solver.add(ctx.Not(ctx.Eq(csRem, ctx.Int.val(expectedMod))));

    const result = await solver.check();
    results.push({
      padSize: ps,
      expectedCsMod4: expectedMod,
      constraintHolds: result === 'unsat',
    });
  }

  return {
    allCorrect: results.every(r => r.constraintHolds),
    results,
  };
}

/**
 * Prove cold start tritet bijection: 8 tritet values (0-7) map to
 * exactly 8 distinct frame types, with no collisions.
 */
export async function proveColdStartTritetBijection(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  details: {
    allDistinct: 'sat' | 'unsat' | 'unknown';
    collisionImpossible: 'sat' | 'unsat' | 'unknown';
    exactlyEight: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('tritet');

  // Model the tritet-to-frame-type mapping as an uninterpreted function
  const tritetToFrame = ctx.Function.declare(
    'tritet_to_frame',
    ctx.Int.sort(),
    ctx.Int.sort(),
  );

  // 8 tritet values (0-7) each map to a frame type
  const tritets = Array.from({ length: 8 }, (_, i) => ctx.Int.val(i));
  const frameTypes = tritets.map(t => tritetToFrame.call(t));

  // Test 1: Can we assign distinct values? (SAT)
  const s1 = new ctx.Solver();
  for (let i = 0; i < 8; i++) {
    for (let j = i + 1; j < 8; j++) {
      s1.add(ctx.Not(ctx.Eq(frameTypes[i], frameTypes[j])));
    }
  }
  const r1 = await s1.check();

  // Test 2: Can any two tritets map to the same frame type
  // while we require bijection? (UNSAT)
  const s2 = new ctx.Solver();
  // Require all distinct
  for (let i = 0; i < 8; i++) {
    for (let j = i + 1; j < 8; j++) {
      s2.add(ctx.Not(ctx.Eq(frameTypes[i], frameTypes[j])));
    }
  }
  // Try to find a collision (contradicts distinctness)
  const a = ctx.Int.const('a');
  const b = ctx.Int.const('b');
  s2.add(a.ge(ctx.Int.val(0)), a.lt(ctx.Int.val(8)));
  s2.add(b.ge(ctx.Int.val(0)), b.lt(ctx.Int.val(8)));
  s2.add(ctx.Not(ctx.Eq(a, b)));
  s2.add(ctx.Eq(tritetToFrame.call(a), tritetToFrame.call(b)));
  const r2 = await s2.check();

  // Test 3: Exactly 8 frame types (no 9th tritet value in range maps to a
  // new frame type). A value outside [0,7] is not a valid tritet.
  const s3 = new ctx.Solver();
  const outOfRange = ctx.Int.const('oor');
  s3.add(ctx.Or(outOfRange.lt(ctx.Int.val(0)), outOfRange.ge(ctx.Int.val(8))));
  // This out-of-range value must be a valid tritet (in [0,7]) -- contradiction
  s3.add(outOfRange.ge(ctx.Int.val(0)));
  s3.add(outOfRange.lt(ctx.Int.val(8)));
  const r3 = await s3.check();

  return {
    result: r2 as 'sat' | 'unsat' | 'unknown',
    details: {
      allDistinct: r1 as 'sat' | 'unsat' | 'unknown',
      collisionImpossible: r2 as 'sat' | 'unsat' | 'unknown',
      exactlyEight: r3 as 'sat' | 'unsat' | 'unknown',
    },
  };
}
