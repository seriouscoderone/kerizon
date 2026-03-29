import { describe, it, expect } from 'vitest';
import { parseStream } from '../../src/composition/parser.js';
import { Serder } from '../../src/composition/serder.js';
import { Siger } from '../../src/primitives/siger.js';
import { Signer } from '../../src/primitives/signer.js';
import { MtrDex, CtrDex_1_0, CtrDex_2_0 } from '../../src/primitives/code-table.js';
import { b64Index } from '../../src/primitives/matter.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a count into 2 B64 characters. */
function encodeCount(n: number): string {
  return b64Index(Math.floor(n / 64)) + b64Index(n % 64);
}

/** Build a simple icp Serder with a known key. */
async function makeIcp(): Promise<{ serder: Serder; signer: Signer }> {
  const signer = await Signer.generate();
  const serder = Serder.fromKed({
    v: '',
    t: 'icp',
    d: '',
    i: '',
    s: '0',
    kt: '1',
    k: [signer.verfer.qb64],
    nt: '1',
    n: ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'],
    bt: '0',
    b: [],
    c: [],
    a: [],
  });
  return { serder, signer };
}

/** Build a kerizon-format CESR stream (JSON + `-A` counter + sigs). */
async function buildKerizonStream(
  serder: Serder,
  signer: Signer,
): Promise<Uint8Array> {
  const sigBytes = await signer.sign(serder.raw);
  const siger = Siger.create({ raw: sigBytes, index: 0 });

  // kerizon format: JSON body + -A<count><sig>
  const count = encodeCount(siger.qb64.length / 4);
  const stream = new TextDecoder().decode(serder.raw) +
    `${CtrDex_1_0.ControllerIdxSigs}${count}${siger.qb64}`;
  return new TextEncoder().encode(stream);
}

/** Build a kli-format CESR stream (JSON + `-V` wrapper + `-A` counter + sigs). */
async function buildKliStream(
  serder: Serder,
  signer: Signer,
): Promise<Uint8Array> {
  const sigBytes = await signer.sign(serder.raw);
  const siger = Siger.create({ raw: sigBytes, index: 0 });

  // Inner: -A<count><sig>
  const innerCount = encodeCount(siger.qb64.length / 4);
  const inner = `${CtrDex_1_0.ControllerIdxSigs}${innerCount}${siger.qb64}`;

  // Outer: -V<totalQuadlets> wrapping the inner
  const totalQuadlets = inner.length / 4;
  const outerCount = encodeCount(totalQuadlets);
  const stream = new TextDecoder().decode(serder.raw) +
    `${CtrDex_1_0.AttachmentGroup}${outerCount}${inner}`;
  return new TextEncoder().encode(stream);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('parseStream', () => {
  it('parses a single message in kerizon format (-A direct)', async () => {
    const { serder, signer } = await makeIcp();
    const data = await buildKerizonStream(serder, signer);

    const messages = parseStream(data);
    expect(messages).toHaveLength(1);
    expect(messages[0].serder.said).toBe(serder.said);
    expect(messages[0].serder.ilk).toBe('icp');
    expect(messages[0].sigers).toHaveLength(1);
    expect(messages[0].sigers[0].index).toBe(0);
  });

  it('parses a single message in kli format (-V wrapper)', async () => {
    const { serder, signer } = await makeIcp();
    const data = await buildKliStream(serder, signer);

    const messages = parseStream(data);
    expect(messages).toHaveLength(1);
    expect(messages[0].serder.said).toBe(serder.said);
    expect(messages[0].sigers).toHaveLength(1);
    expect(messages[0].sigers[0].index).toBe(0);
  });

  it('parses multiple concatenated messages', async () => {
    const { serder: serder1, signer: signer1 } = await makeIcp();
    const { serder: serder2, signer: signer2 } = await makeIcp();

    const data1 = await buildKerizonStream(serder1, signer1);
    const data2 = await buildKerizonStream(serder2, signer2);

    // Concatenate
    const combined = new Uint8Array(data1.length + data2.length);
    combined.set(data1, 0);
    combined.set(data2, data1.length);

    const messages = parseStream(combined);
    expect(messages).toHaveLength(2);
    expect(messages[0].serder.said).toBe(serder1.said);
    expect(messages[1].serder.said).toBe(serder2.said);
  });

  it('round-trips: sign and verify extracted signatures', async () => {
    const { serder, signer } = await makeIcp();
    const data = await buildKerizonStream(serder, signer);

    const messages = parseStream(data);
    const msg = messages[0];

    // Verify the extracted signature against the serder raw bytes
    const verfer = signer.verfer;
    const valid = await verfer.verify(msg.sigers[0].raw, msg.serder.raw);
    expect(valid).toBe(true);
  });

  it('handles multiple signatures per message', async () => {
    const signer0 = await Signer.generate();
    const signer1 = await Signer.generate();

    const serder = Serder.fromKed({
      v: '',
      t: 'icp',
      d: '',
      i: '',
      s: '0',
      kt: '2',
      k: [signer0.verfer.qb64, signer1.verfer.qb64],
      nt: '2',
      n: ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj', 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'],
      bt: '0',
      b: [],
      c: [],
      a: [],
    });

    const sig0 = await signer0.sign(serder.raw);
    const sig1 = await signer1.sign(serder.raw);
    const siger0 = Siger.create({ raw: sig0, index: 0 });
    const siger1 = Siger.create({ raw: sig1, index: 1 });

    const count = encodeCount((siger0.qb64.length + siger1.qb64.length) / 4);
    const stream = new TextDecoder().decode(serder.raw) +
      `${CtrDex_1_0.ControllerIdxSigs}${count}${siger0.qb64}${siger1.qb64}`;
    const data = new TextEncoder().encode(stream);

    const messages = parseStream(data);
    expect(messages).toHaveLength(1);
    expect(messages[0].sigers).toHaveLength(2);
    expect(messages[0].sigers[0].index).toBe(0);
    expect(messages[0].sigers[1].index).toBe(1);
  });

  it('returns empty array for empty input', () => {
    const messages = parseStream(new Uint8Array(0));
    expect(messages).toHaveLength(0);
  });

  it('handles mixed format stream (kli first, kerizon second)', async () => {
    const { serder: s1, signer: sn1 } = await makeIcp();
    const { serder: s2, signer: sn2 } = await makeIcp();

    const d1 = await buildKliStream(s1, sn1);
    const d2 = await buildKerizonStream(s2, sn2);

    const combined = new Uint8Array(d1.length + d2.length);
    combined.set(d1, 0);
    combined.set(d2, d1.length);

    const messages = parseStream(combined);
    expect(messages).toHaveLength(2);
    expect(messages[0].serder.said).toBe(s1.said);
    expect(messages[1].serder.said).toBe(s2.said);
    expect(messages[0].sigers).toHaveLength(1);
    expect(messages[1].sigers).toHaveLength(1);
  });
});
