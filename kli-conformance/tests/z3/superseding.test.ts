import { describe, it, expect } from 'vitest';
import {
  proveRuleA0_PreRotatedPrecedence,
  proveRuleA1_NonDelegatedNoSupersede,
  proveRuleA2_InteractionNoSupersede,
  proveB1B2B3_DelegatedCascade,
} from '../../src/z3/superseding.js';

describe('Z3: superseding recovery decision cascade', () => {
  describe('Rule A0: pre-rotated key precedence', () => {
    it('pre-rotated keys supersede compromised keys', async () => {
      const result = await proveRuleA0_PreRotatedPrecedence();
      expect(result.details.preRotatedWins).toBe('sat');
    });

    it('compromised keys cannot supersede pre-rotated keys', async () => {
      const result = await proveRuleA0_PreRotatedPrecedence();
      expect(result.details.compromisedCannotWin).toBe('unsat');
    });
  });

  describe('Rule A1: non-delegated rotation mutual exclusion', () => {
    it('non-delegated rotation MUST NOT supersede another rotation at same sn', async () => {
      const result = await proveRuleA1_NonDelegatedNoSupersede();
      // UNSAT: no assignment satisfies the contradictory constraints
      expect(result.result).toBe('unsat');
    });
  });

  describe('Rule A2: interaction event restriction', () => {
    it('interaction event MUST NOT supersede any event', async () => {
      const result = await proveRuleA2_InteractionNoSupersede();
      // UNSAT: interaction cannot supersede
      expect(result.result).toBe('unsat');
    });
  });

  describe('Rules B1-B3: delegated event cascade', () => {
    it('B1: first-seen wins when anchors are equal', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.details.b1FirstSeenWins).toBe('sat');
    });

    it('B2: earlier delegation anchor supersedes later', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.details.b2EarlierAnchorSupersedes).toBe('sat');
    });

    it('B3: recovery with later anchor supersedes', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.details.b3LaterAnchorSupersedes).toBe('sat');
    });

    it('two winners are impossible', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.details.twoWinnersImpossible).toBe('unsat');
    });

    it('no winner is impossible for distinct events', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.details.noWinnerImpossible).toBe('unsat');
    });

    it('cascade produces exactly one winner (total ordering)', async () => {
      const result = await proveB1B2B3_DelegatedCascade();
      expect(result.exactlyOneWinner).toBe(true);
    });
  });
});
