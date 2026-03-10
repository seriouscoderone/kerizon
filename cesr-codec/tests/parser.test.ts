import { describe, test, expect } from 'vitest';
import { parseBytes, isPrimitiveTuple } from '../src/parser.js';
import { Matter } from '../src/matter.js';
import { Indexer } from '../src/indexer.js';
import { Counter } from '../src/counter.js';

function buildCesrMessage(ked: Record<string, unknown>, attachmentQb64: string): Uint8Array {
  const jsonStr = JSON.stringify(ked);
  const size = jsonStr.length.toString(16).padStart(6, '0');
  // Inject version string
  const versioned = { v: `KERI10JSON${size}_`, ...ked };
  const body = JSON.stringify(versioned);
  // Recalculate with actual body size
  const actualSize = body.length.toString(16).padStart(6, '0');
  const finalBody = body.replace(/KERI10JSON[0-9a-f]{6}_/, `KERI10JSON${actualSize}_`);
  return new TextEncoder().encode(finalBody + attachmentQb64);
}

describe('parseBytes', () => {
  test('parses a CESR frame with JSON body and indexed sig attachment', () => {
    const sigRaw = new Uint8Array(64).fill(0x42);
    const indexer = new Indexer({ code: 'A', raw: sigRaw, index: 0 });
    const counter = new Counter({ code: '-A', count: 1 });

    const ked = { t: 'icp', d: 'SAID123' };
    const attachments = counter.qb64 + indexer.qb64;
    const bytes = buildCesrMessage(ked, attachments);

    const emissions = parseBytes(bytes);
    expect(emissions.length).toBe(1);
    expect(emissions[0].type).toBe('frame');

    const frame = emissions[0].frame;
    expect(frame.body.ked['t']).toBe('icp');
    expect(frame.body.raw.length).toBeGreaterThan(0);

    expect(frame.attachments.length).toBe(1);
    expect(frame.attachments[0].name).toBe('ControllerIdxSigs');
    expect(frame.attachments[0].count).toBe(1);
    expect(frame.attachments[0].items.length).toBe(1);

    const item = frame.attachments[0].items[0];
    expect(isPrimitiveTuple(item)).toBe(true);
    expect(item[0] instanceof Indexer).toBe(true);
    expect((item[0] as Indexer).raw).toEqual(sigRaw);
  });

  test('parses multiple indexed sigs', () => {
    const sigs = [
      new Indexer({ code: 'A', raw: new Uint8Array(64).fill(0x11), index: 0 }),
      new Indexer({ code: 'A', raw: new Uint8Array(64).fill(0x22), index: 1 }),
      new Indexer({ code: 'A', raw: new Uint8Array(64).fill(0x33), index: 2 }),
    ];
    const counter = new Counter({ code: '-A', count: 3 });
    const attachments = counter.qb64 + sigs.map(s => s.qb64).join('');

    const ked = { t: 'rot', d: 'SAID456' };
    const bytes = buildCesrMessage(ked, attachments);

    const emissions = parseBytes(bytes);
    const frame = emissions[0].frame;
    expect(frame.attachments[0].items.length).toBe(3);

    for (let i = 0; i < 3; i++) {
      const indexer = frame.attachments[0].items[i][0] as Indexer;
      expect(indexer.index).toBe(i);
    }
  });

  test('parses witness indexed sigs (-B counter)', () => {
    const sig = new Indexer({ code: 'B', raw: new Uint8Array(64).fill(0x55), index: 0 });
    const counter = new Counter({ code: '-B', count: 1 });
    const attachments = counter.qb64 + sig.qb64;

    const ked = { t: 'icp' };
    const bytes = buildCesrMessage(ked, attachments);

    const emissions = parseBytes(bytes);
    const frame = emissions[0].frame;
    expect(frame.attachments[0].name).toBe('WitnessIdxSigs');
    expect(frame.attachments[0].items[0][0] instanceof Indexer).toBe(true);
  });

  test('isPrimitiveTuple returns false for non-arrays', () => {
    expect(isPrimitiveTuple(null)).toBe(false);
    expect(isPrimitiveTuple(42)).toBe(false);
    expect(isPrimitiveTuple('foo')).toBe(false);
    expect(isPrimitiveTuple([])).toBe(false);
    expect(isPrimitiveTuple([42])).toBe(false);
  });

  test('isPrimitiveTuple returns true for primitive arrays', () => {
    const m = new Matter({ code: 'D', raw: new Uint8Array(32) });
    const i = new Indexer({ code: 'A', raw: new Uint8Array(64), index: 0 });
    expect(isPrimitiveTuple([m])).toBe(true);
    expect(isPrimitiveTuple([i])).toBe(true);
    expect(isPrimitiveTuple([m, m])).toBe(true);
  });

  test('body.raw can be used for signature verification', () => {
    const ked = { t: 'icp', v: 'placeholder' };
    const counter = new Counter({ code: '-A', count: 0 });
    const bytes = buildCesrMessage(ked, counter.qb64);

    const emissions = parseBytes(bytes);
    const frame = emissions[0].frame;
    // raw should be valid UTF-8 JSON
    const rawStr = new TextDecoder().decode(frame.body.raw);
    expect(() => JSON.parse(rawStr)).not.toThrow();
  });
});
