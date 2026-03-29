import { describe, it, expect } from 'vitest';
import { shouldAccept } from '../../src/discovery/bada.js';
import type { BadaRecord } from '../../src/discovery/types.js';

describe('shouldAccept (BADA policy)', () => {
  it('accepts when no existing record', () => {
    const incoming: BadaRecord = { tier: 'unsigned', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(null, incoming)).toBe(true);
  });

  it('signed-anchored beats signed', () => {
    const existing: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed-anchored', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(true);
  });

  it('signed beats unsigned', () => {
    const existing: BadaRecord = { tier: 'unsigned', datetime: '2026-03-29T00:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(true);
  });

  it('rejects lower tier', () => {
    const existing: BadaRecord = { tier: 'signed-anchored', datetime: '2026-03-29T00:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(false);
  });

  it('same tier: newer datetime wins', () => {
    const existing: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed', datetime: '2026-03-29T01:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(true);
  });

  it('same tier: older datetime rejected', () => {
    const existing: BadaRecord = { tier: 'signed', datetime: '2026-03-29T01:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(false);
  });

  it('same tier same datetime: rejected (not strictly newer)', () => {
    const existing: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    const incoming: BadaRecord = { tier: 'signed', datetime: '2026-03-29T00:00:00Z', data: {} };
    expect(shouldAccept(existing, incoming)).toBe(false);
  });
});
