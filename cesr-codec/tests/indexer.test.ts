import { describe, test, expect } from 'vitest';
import { Indexer, parseIndexerFromText, INDEXED_CODE_TABLE } from '../src/indexer.js';

describe('Indexer class', () => {
  test('construct from code + raw + index', () => {
    const raw = new Uint8Array(64).fill(0x42);
    const indexer = new Indexer({ code: 'A', raw, index: 5 });
    expect(indexer.code).toBe('A');
    expect(indexer.raw).toEqual(raw);
    expect(indexer.index).toBe(5);
    expect(indexer.ondex).toBe(5); // defaults to index when not specified
  });

  test('qb64 encoding for code A', () => {
    const raw = new Uint8Array(64).fill(0);
    const indexer = new Indexer({ code: 'A', raw, index: 0 });
    const qb64 = indexer.qb64;
    expect(qb64.length).toBe(88);
    expect(qb64[0]).toBe('A'); // hard code
    expect(qb64[1]).toBe('A'); // soft = intToB64(0, 1) = 'A'
  });

  test('index encoding in soft part', () => {
    const raw = new Uint8Array(64).fill(0);
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    for (let idx = 0; idx < 64; idx++) {
      const indexer = new Indexer({ code: 'A', raw, index: idx });
      expect(indexer.qb64[1]).toBe(B64[idx]);
    }
  });

  test('qb64 round-trip for code A', () => {
    const raw = new Uint8Array(64).fill(0xAB);
    const i1 = new Indexer({ code: 'A', raw, index: 7 });
    const i2 = new Indexer({ qb64: i1.qb64 });
    expect(i2.code).toBe('A');
    expect(i2.raw).toEqual(raw);
    expect(i2.index).toBe(7);
  });

  test('qb64b round-trip', () => {
    const raw = new Uint8Array(64).fill(0xCD);
    const i1 = new Indexer({ code: 'A', raw, index: 3 });
    const i2 = new Indexer({ qb64b: i1.qb64b });
    expect(i2.code).toBe('A');
    expect(i2.raw).toEqual(raw);
    expect(i2.index).toBe(3);
  });

  test('code B (both same) round-trip', () => {
    const raw = new Uint8Array(64).fill(0x55);
    const i1 = new Indexer({ code: 'B', raw, index: 10 });
    const i2 = new Indexer({ qb64: i1.qb64 });
    expect(i2.code).toBe('B');
    expect(i2.raw).toEqual(raw);
    expect(i2.index).toBe(10);
    expect(i2.ondex).toBe(10); // both same
  });

  test('instanceof check works', () => {
    const raw = new Uint8Array(64).fill(0);
    const i = new Indexer({ code: 'A', raw, index: 0 });
    expect(i instanceof Indexer).toBe(true);
  });

  test('throws on unknown indexer code', () => {
    expect(() => new Indexer({ code: 'Z', raw: new Uint8Array(64), index: 0 }))
      .toThrow('Unknown indexer code');
  });

  test('parseIndexerFromText works', () => {
    const raw = new Uint8Array(64).fill(0x33);
    const i1 = new Indexer({ code: 'A', raw, index: 12 });
    const encoded = new TextEncoder().encode(i1.qb64);
    const i2 = parseIndexerFromText(encoded);
    expect(i2.code).toBe('A');
    expect(i2.raw).toEqual(raw);
    expect(i2.index).toBe(12);
    expect(i2 instanceof Indexer).toBe(true);
  });

  test('fullSize matches table', () => {
    for (const entry of INDEXED_CODE_TABLE) {
      const raw = new Uint8Array(64).fill(0);
      const i = new Indexer({ code: entry.code, raw, index: 0 });
      expect(i.fullSize).toBe(entry.fullSize);
    }
  });

  test('big code 0A with separate index/ondex', () => {
    // 0A: hs=2, ss=2, os=1 → ondex (1 char) + index (1 char)
    const raw = new Uint8Array(64).fill(0x42);
    const i1 = new Indexer({ code: '0A', raw, index: 5, ondex: 3 });
    expect(i1.index).toBe(5);
    expect(i1.ondex).toBe(3);
    const i2 = new Indexer({ qb64: i1.qb64 });
    expect(i2.index).toBe(5);
    expect(i2.ondex).toBe(3);
  });
});
