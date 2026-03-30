import { describe, it, expect } from 'vitest';
import { classifyPrivacyLevel, validateDisclosure } from '../../src/privacy/disclosure.js';
import type { DisclosureType } from '../../src/privacy/types.js';

describe('classifyPrivacyLevel', () => {
  it('returns public when no u field', () => {
    const acdc = { v: 'ACDC10JSON000000_', d: 'ESaid', i: 'EIssuer', s: 'ESchema' };
    expect(classifyPrivacyLevel(acdc)).toBe('public');
  });

  it('returns private when u field is non-empty', () => {
    const acdc = { v: 'ACDC10JSON000000_', d: 'ESaid', i: 'EIssuer', s: 'ESchema', u: 'AUuidNonce123' };
    expect(classifyPrivacyLevel(acdc)).toBe('private');
  });

  it('returns metadata when u field is empty string', () => {
    const acdc = { v: 'ACDC10JSON000000_', d: 'ESaid', i: 'EIssuer', s: 'ESchema', u: '' };
    expect(classifyPrivacyLevel(acdc)).toBe('metadata');
  });
});

describe('validateDisclosure', () => {
  it('returns true when SAIDs match', () => {
    const compact = { d: 'ESaidMatch_____________________________________' };
    const expanded = { d: 'ESaidMatch_____________________________________', a: { name: 'Alice' } };
    expect(validateDisclosure(compact, expanded)).toBe(true);
  });

  it('returns false when SAIDs differ', () => {
    const compact = { d: 'ESaidA________________________________________' };
    const expanded = { d: 'ESaidB________________________________________' };
    expect(validateDisclosure(compact, expanded)).toBe(false);
  });
});

describe('DisclosureType', () => {
  it('all four disclosure types are valid', () => {
    const types: DisclosureType[] = ['full', 'compact', 'partial', 'selective'];
    expect(types).toHaveLength(4);
    // Type-level assertion: if DisclosureType excluded any of these,
    // the assignment above would cause a compile error.
  });
});
