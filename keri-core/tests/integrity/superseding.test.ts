import { describe, it, expect } from 'vitest';
import { SupersedingRule, canSupersede } from '../../src/integrity/superseding.js';

describe('canSupersede', () => {
  // A2: interaction events cannot supersede anything
  it('A2: ixn cannot supersede (returns None)', () => {
    const superseding = { type: 'ixn' as const, sn: 5, preRotated: false };
    const superseded = { type: 'ixn' as const, sn: 5, preRotated: false };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.None);
  });

  // Recovery: rotation supersedes interaction
  it('Recovery: rot supersedes ixn', () => {
    const superseding = { type: 'rot' as const, sn: 5, preRotated: true };
    const superseded = { type: 'ixn' as const, sn: 5, preRotated: false };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.Recovery);
  });

  // A0: pre-rotated rotation supersedes non-pre-rotated rotation
  it('A0: pre-rotated rot wins over non-pre-rotated rot', () => {
    const superseding = { type: 'rot' as const, sn: 5, preRotated: true };
    const superseded = { type: 'rot' as const, sn: 5, preRotated: false };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.A0);
  });

  // A1: rot vs rot, both pre-rotated = no superseding
  it('A1: rot vs rot both pre-rotated yields None', () => {
    const superseding = { type: 'rot' as const, sn: 5, preRotated: true };
    const superseded = { type: 'rot' as const, sn: 5, preRotated: true };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.None);
  });

  // Edge: rot vs rot, neither pre-rotated = None
  it('rot vs rot, neither pre-rotated yields None', () => {
    const superseding = { type: 'rot' as const, sn: 5, preRotated: false };
    const superseded = { type: 'rot' as const, sn: 5, preRotated: false };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.None);
  });

  // Edge: non-pre-rotated rot cannot supersede pre-rotated rot
  it('non-pre-rotated rot cannot supersede pre-rotated rot', () => {
    const superseding = { type: 'rot' as const, sn: 5, preRotated: false };
    const superseded = { type: 'rot' as const, sn: 5, preRotated: true };

    expect(canSupersede(superseding, superseded)).toBe(SupersedingRule.None);
  });
});
