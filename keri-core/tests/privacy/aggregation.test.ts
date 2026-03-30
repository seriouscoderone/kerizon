import { describe, it, expect } from 'vitest';
import {
  computeSadPathDigest,
  computeAggregate,
  verifyInclusion,
} from '../../src/privacy/aggregation.js';

describe('computeSadPathDigest', () => {
  it('computes digest for a nested field path', () => {
    const sad = { a: { b: { c: 'hello' } } };
    const digest = computeSadPathDigest(sad, ['a', 'b', 'c']);
    expect(digest).toBeDefined();
    expect(typeof digest).toBe('string');
    expect(digest.length).toBeGreaterThan(0);
  });

  it('deep path works and is deterministic', () => {
    const sad = { x: { y: { z: 42 } } };
    const d1 = computeSadPathDigest(sad, ['x', 'y', 'z']);
    const d2 = computeSadPathDigest(sad, ['x', 'y', 'z']);
    expect(d1).toBe(d2);
  });

  it('throws on invalid path', () => {
    const sad = { a: 'value' };
    expect(() => computeSadPathDigest(sad, ['a', 'missing'])).toThrow(
      'Invalid path',
    );
  });
});

describe('computeAggregate', () => {
  it('is deterministic', () => {
    const digests = ['EDigest1', 'EDigest2', 'EDigest3'];
    const a1 = computeAggregate(digests);
    const a2 = computeAggregate(digests);
    expect(a1).toBe(a2);
  });
});

describe('verifyInclusion', () => {
  it('returns true when field digest is in the aggregate', () => {
    const sad = { name: 'Alice', age: 30, role: 'admin' };
    const d1 = computeSadPathDigest(sad, ['name']);
    const d2 = computeSadPathDigest(sad, ['age']);
    const d3 = computeSadPathDigest(sad, ['role']);
    const allDigests = [d1, d2, d3];
    const aggregate = computeAggregate(allDigests);

    expect(verifyInclusion(d1, allDigests, aggregate)).toBe(true);
  });

  it('returns false when aggregate does not match', () => {
    const sad = { name: 'Alice', age: 30 };
    const d1 = computeSadPathDigest(sad, ['name']);
    const d2 = computeSadPathDigest(sad, ['age']);
    const allDigests = [d1, d2];

    expect(verifyInclusion(d1, allDigests, 'EWrongAggregate')).toBe(false);
  });
});
