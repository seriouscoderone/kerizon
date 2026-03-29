/**
 * Z3 constraints for the KERI superseding recovery decision cascade.
 *
 * Models the rules from the KERI spec that determine which event "wins"
 * when multiple events compete at the same sequence number:
 *
 * Rule A0: Pre-rotated keys take precedence over compromised keys
 * Rule A1: Non-delegated rotation MUST NOT supersede another rotation at same sn
 * Rule A2: Interaction event MUST NOT supersede any event
 * Rules B1-B3: Delegated event cascade with first-seen, anchor-earlier, anchor-later
 *
 * See KERI spec section on superseding recovery rules.
 */

import { init, type Z3HighLevel } from 'z3-solver';

let z3Instance: Z3HighLevel | null = null;

async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Instance) z3Instance = await init();
  return z3Instance;
}

/**
 * Rule A0: Authentic (pre-rotated) keys take precedence over compromised keys.
 * A rotation event signed with pre-rotated keys supersedes one signed with
 * compromised current keys at the same sn.
 */
export async function proveRuleA0_PreRotatedPrecedence(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
  details: {
    preRotatedWins: 'sat' | 'unsat' | 'unknown';
    compromisedCannotWin: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('a0');

  const isPreRotated = ctx.Bool.const('is_pre_rotated');
  const isCompromised = ctx.Bool.const('is_compromised');
  const sameSn = ctx.Bool.const('same_sn');
  const supersedes = ctx.Bool.const('supersedes');

  // Definition: supersedes iff pre-rotated AND same sn AND other is compromised
  const definition = ctx.Eq(
    supersedes,
    ctx.And(isPreRotated, sameSn, isCompromised),
  );

  // Test 1: Pre-rotated key at same sn vs compromised -> supersedes (SAT)
  const s1 = new ctx.Solver();
  s1.add(definition);
  s1.add(isPreRotated, sameSn, isCompromised, supersedes);
  const r1 = await s1.check();

  // Test 2: Compromised key cannot supersede pre-rotated (UNSAT)
  const s2 = new ctx.Solver();
  s2.add(definition);
  s2.add(ctx.Not(isPreRotated), sameSn, ctx.Not(isCompromised), supersedes);
  const r2 = await s2.check();

  return {
    result: r1 as 'sat' | 'unsat' | 'unknown',
    details: {
      preRotatedWins: r1 as 'sat' | 'unsat' | 'unknown',
      compromisedCannotWin: r2 as 'sat' | 'unsat' | 'unknown',
    },
  };
}

/**
 * Rule A1: Non-delegated rotation MUST NOT supersede another rotation at same sn.
 * Once a non-delegated rotation is accepted, no other rotation at the same sn
 * can replace it (first-seen wins for non-delegated).
 */
export async function proveRuleA1_NonDelegatedNoSupersede(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('a1');

  const isDelegated = ctx.Bool.const('is_delegated');
  const isRotation = ctx.Bool.const('is_rotation');
  const otherIsRotation = ctx.Bool.const('other_is_rotation');
  const sameSn = ctx.Bool.const('same_sn');
  const canSupersede = ctx.Bool.const('can_supersede');

  // Rule A1: for non-delegated, rotation cannot supersede rotation at same sn
  // canSupersede = false when NOT delegated AND both are rotations at same sn
  const ruleA1 = ctx.Implies(
    ctx.And(ctx.Not(isDelegated), isRotation, otherIsRotation, sameSn),
    ctx.Not(canSupersede),
  );

  // Try to find a case where non-delegated rotation supersedes rotation at same sn
  const solver = new ctx.Solver();
  solver.add(ruleA1);
  solver.add(ctx.Not(isDelegated));
  solver.add(isRotation);
  solver.add(otherIsRotation);
  solver.add(sameSn);
  solver.add(canSupersede);

  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}

/**
 * Rule A2: Interaction event MUST NOT supersede any event.
 * An interaction (ixn) event can never supersede any other event type.
 */
export async function proveRuleA2_InteractionNoSupersede(): Promise<{
  result: 'sat' | 'unsat' | 'unknown';
}> {
  const { Context } = await getZ3();
  const ctx = new Context('a2');

  const isInteraction = ctx.Bool.const('is_interaction');
  const canSupersede = ctx.Bool.const('can_supersede');

  // Rule A2: interaction events never supersede
  const ruleA2 = ctx.Implies(isInteraction, ctx.Not(canSupersede));

  // Try to find a case where interaction supersedes
  const solver = new ctx.Solver();
  solver.add(ruleA2);
  solver.add(isInteraction);
  solver.add(canSupersede);

  const result = await solver.check();
  return { result: result as 'sat' | 'unsat' | 'unknown' };
}

/**
 * Rules B1-B3: Delegated event superseding cascade produces exactly one winner.
 *
 * For delegated events at the same sn, the cascade is:
 *   B1: First seen wins (default)
 *   B2: Earlier delegation anchor supersedes later
 *   B3: Later delegation anchor supersedes earlier (recovery)
 *
 * Each rule only applies when its precondition holds. Exactly one rule fires
 * and it produces a total ordering (exactly one winner among candidates).
 */
export async function proveB1B2B3_DelegatedCascade(): Promise<{
  exactlyOneWinner: boolean;
  details: {
    b1FirstSeenWins: 'sat' | 'unsat' | 'unknown';
    b2EarlierAnchorSupersedes: 'sat' | 'unsat' | 'unknown';
    b3LaterAnchorSupersedes: 'sat' | 'unsat' | 'unknown';
    twoWinnersImpossible: 'sat' | 'unsat' | 'unknown';
    noWinnerImpossible: 'sat' | 'unsat' | 'unknown';
  };
}> {
  const { Context } = await getZ3();
  const ctx = new Context('b123');

  // Two competing delegated events at the same sn
  const firstSeenA = ctx.Int.const('first_seen_a'); // timestamp/order of first-seen
  const firstSeenB = ctx.Int.const('first_seen_b');
  const anchorSnA = ctx.Int.const('anchor_sn_a');   // delegation anchor sn
  const anchorSnB = ctx.Int.const('anchor_sn_b');
  const isRecoveryA = ctx.Bool.const('is_recovery_a');
  const isRecoveryB = ctx.Bool.const('is_recovery_b');

  const aWins = ctx.Bool.const('a_wins');
  const bWins = ctx.Bool.const('b_wins');

  // Domain constraints
  const domain = [
    firstSeenA.ge(ctx.Int.val(0)),
    firstSeenB.ge(ctx.Int.val(0)),
    anchorSnA.ge(ctx.Int.val(0)),
    anchorSnB.ge(ctx.Int.val(0)),
    // They are distinct events
    ctx.Not(ctx.And(
      ctx.Eq(firstSeenA, firstSeenB),
      ctx.Eq(anchorSnA, anchorSnB),
    )),
  ];

  // B3 takes priority: if one is recovery with later anchor, it wins
  const b3_aWins = ctx.And(isRecoveryA, anchorSnA.gt(anchorSnB));
  const b3_bWins = ctx.And(isRecoveryB, anchorSnB.gt(anchorSnA));

  // B2: earlier anchor wins (when no recovery override)
  const noRecoveryOverride = ctx.And(ctx.Not(b3_aWins), ctx.Not(b3_bWins));
  const b2_aWins = ctx.And(noRecoveryOverride, anchorSnA.lt(anchorSnB));
  const b2_bWins = ctx.And(noRecoveryOverride, anchorSnB.lt(anchorSnA));

  // B1: first-seen wins (when anchors are equal and no recovery)
  const noAnchorDifference = ctx.And(
    noRecoveryOverride,
    ctx.Eq(anchorSnA, anchorSnB),
  );
  const b1_aWins = ctx.And(noAnchorDifference, firstSeenA.lt(firstSeenB));
  const b1_bWins = ctx.And(noAnchorDifference, firstSeenB.lt(firstSeenA));

  // Winner determination
  const aWinsDef = ctx.Eq(aWins, ctx.Or(b3_aWins, b2_aWins, b1_aWins));
  const bWinsDef = ctx.Eq(bWins, ctx.Or(b3_bWins, b2_bWins, b1_bWins));

  // Test B1: first-seen scenario
  const s1 = new ctx.Solver();
  s1.add(...domain, aWinsDef, bWinsDef);
  s1.add(ctx.Eq(anchorSnA, anchorSnB)); // same anchor
  s1.add(ctx.Not(isRecoveryA), ctx.Not(isRecoveryB)); // no recovery
  s1.add(firstSeenA.lt(firstSeenB)); // A seen first
  s1.add(aWins);
  const r1 = await s1.check();

  // Test B2: earlier anchor scenario
  const s2 = new ctx.Solver();
  s2.add(...domain, aWinsDef, bWinsDef);
  s2.add(anchorSnA.lt(anchorSnB)); // A has earlier anchor
  s2.add(ctx.Not(isRecoveryA), ctx.Not(isRecoveryB)); // no recovery
  s2.add(aWins);
  const r2 = await s2.check();

  // Test B3: recovery with later anchor
  const s3 = new ctx.Solver();
  s3.add(...domain, aWinsDef, bWinsDef);
  s3.add(isRecoveryA); // A is recovery
  s3.add(anchorSnA.gt(anchorSnB)); // A has later anchor
  s3.add(aWins);
  const r3 = await s3.check();

  // Test: can both win simultaneously? (UNSAT)
  const s4 = new ctx.Solver();
  s4.add(...domain, aWinsDef, bWinsDef);
  s4.add(aWins, bWins);
  const r4 = await s4.check();

  // Test: can neither win? (UNSAT when events are truly distinct with
  // different first-seen times)
  const s5 = new ctx.Solver();
  s5.add(...domain, aWinsDef, bWinsDef);
  s5.add(ctx.Not(aWins), ctx.Not(bWins));
  s5.add(ctx.Not(ctx.Eq(firstSeenA, firstSeenB))); // distinct first-seen
  const r5 = await s5.check();

  return {
    exactlyOneWinner: r4 === 'unsat' && r5 === 'unsat',
    details: {
      b1FirstSeenWins: r1 as 'sat' | 'unsat' | 'unknown',
      b2EarlierAnchorSupersedes: r2 as 'sat' | 'unsat' | 'unknown',
      b3LaterAnchorSupersedes: r3 as 'sat' | 'unsat' | 'unknown',
      twoWinnersImpossible: r4 as 'sat' | 'unsat' | 'unknown',
      noWinnerImpossible: r5 as 'sat' | 'unsat' | 'unknown',
    },
  };
}
