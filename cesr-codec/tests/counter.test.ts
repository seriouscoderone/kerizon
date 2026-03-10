import { describe, test, expect } from 'vitest';
import { Counter, parseCounterFromText } from '../src/counter.js';

describe('Counter class', () => {
  test('construct from code + count', () => {
    const c = new Counter({ code: '-A', count: 3 });
    expect(c.code).toBe('-A');
    expect(c.count).toBe(3);
    expect(c.name).toBe('ControllerIdxSigs');
  });

  test('qb64 encoding', () => {
    const c = new Counter({ code: '-A', count: 1 });
    expect(c.qb64).toBe('-AAB'); // -A + intToB64(1, 2) = 'AB'
    expect(c.fullSize).toBe(4);
  });

  test('qb64 round-trip', () => {
    for (let count = 0; count < 64; count++) {
      const c1 = new Counter({ code: '-A', count });
      const c2 = new Counter({ qb64: c1.qb64 });
      expect(c2.code).toBe('-A');
      expect(c2.count).toBe(count);
    }
  });

  test('qb64b round-trip', () => {
    const c1 = new Counter({ code: '-B', count: 10 });
    const c2 = new Counter({ qb64b: c1.qb64b });
    expect(c2.code).toBe('-B');
    expect(c2.count).toBe(10);
    expect(c2.name).toBe('WitnessIdxSigs');
  });

  test('parseCounterFromText works', () => {
    const c1 = new Counter({ code: '-A', count: 5 });
    const encoded = new TextEncoder().encode(c1.qb64);
    const c2 = parseCounterFromText(encoded);
    expect(c2.code).toBe('-A');
    expect(c2.count).toBe(5);
    expect(c2 instanceof Counter).toBe(true);
  });

  test('instanceof check works', () => {
    const c = new Counter({ code: '-A', count: 1 });
    expect(c instanceof Counter).toBe(true);
  });

  test('throws on non-counter code', () => {
    expect(() => new Counter({ qb64: 'DABC' })).toThrow('Not a counter');
  });

  test('large count values', () => {
    const c1 = new Counter({ code: '-A', count: 4095 });
    const c2 = new Counter({ qb64: c1.qb64 });
    expect(c2.count).toBe(4095);
  });
});
