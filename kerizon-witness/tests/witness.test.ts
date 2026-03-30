import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Signer, Siger, Serder, CtrDex_1_0, b64Index } from '@kerizon/cesr';
import { incept } from '@kerizon/keri-core';
import { KerizonWitness } from '../src/witness.js';
import { NedbStore } from '../src/store/nedb-store.js';

/** Encode a short counter: code + 2-char B64 count. */
function encodeCounter(code: string, count: number): string {
  return code + b64Index(Math.floor(count / 64) & 0x3f) + b64Index(count & 0x3f);
}

/** Build a CESR stream from a serder + sigers (controller-indexed-sig format). */
function buildCesr(serder: Serder, sigers: Siger[]): Uint8Array {
  const jsonPart = new TextDecoder().decode(serder.raw);
  // Quadlet count: each sig is 88 chars = 22 quadlets
  const totalQuadlets = sigers.reduce((sum, s) => sum + s.qb64.length / 4, 0);
  const counter = encodeCounter(CtrDex_1_0.ControllerIdxSigs, totalQuadlets);
  const sigsPart = sigers.map(s => s.qb64).join('');
  const full = jsonPart + counter + sigsPart;
  return new TextEncoder().encode(full);
}

describe('KerizonWitness', () => {
  let dbDir: string;
  let store: NedbStore;

  beforeEach(async () => {
    dbDir = await mkdtemp(join(tmpdir(), 'witness-test-'));
    store = new NedbStore(dbDir);
  });

  afterEach(async () => {
    await store.close();
    await rm(dbDir, { recursive: true, force: true });
  });

  it('create() produces a witness with a B-prefix (non-transferable)', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );
    expect(witness.prefix).toBeTruthy();
    expect(witness.prefix.length).toBe(44);
    // Non-transferable Ed25519 basic prefix starts with 'B'
    expect(witness.prefix[0]).toBe('B');
  });

  it('prefix persists across restarts (same store)', async () => {
    const witness1 = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );
    const prefix1 = witness1.prefix;

    // Create a second witness using the same store directory
    const store2 = new NedbStore(dbDir);
    const witness2 = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store2,
    );
    expect(witness2.prefix).toBe(prefix1);
    await store2.close();
  });

  it('processEvent accepts a valid inception and returns receipt', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );

    // Create a controller inception event
    const ctrlSigner = await Signer.generate();
    const ctrlSerder = incept({
      keys: [ctrlSigner.verfer.qb64],
      nextDigests: [],
      nextThreshold: '0',
      witnesses: [witness.prefix],
      witnessThreshold: 1,
    });

    // Sign it
    const sigRaw = await ctrlSigner.sign(ctrlSerder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    // Build CESR stream
    const cesr = buildCesr(ctrlSerder, [siger]);

    const result = await witness.processEvent(cesr);
    expect('receipt' in result).toBe(true);
    if ('receipt' in result) {
      expect(result.eventSaid).toBe(ctrlSerder.said);
      expect(result.receipt.length).toBeGreaterThan(0);
    }
  });

  it('receipt signature is 88 chars (Ed25519 indexed sig)', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );

    const ctrlSigner = await Signer.generate();
    const ctrlSerder = incept({
      keys: [ctrlSigner.verfer.qb64],
      nextDigests: [],
      nextThreshold: '0',
    });

    const sigRaw = await ctrlSigner.sign(ctrlSerder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });
    const cesr = buildCesr(ctrlSerder, [siger]);

    const result = await witness.processEvent(cesr);
    expect('receipt' in result).toBe(true);
    if ('receipt' in result) {
      expect(result.receipt.length).toBe(88);
    }
  });

  it('getOwnKel returns CESR with JSON body + sig attachment', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );

    const kel = witness.getOwnKel();
    expect(kel.length).toBeGreaterThan(0);

    // The CESR stream is: JSON body + counter + signature
    // Extract the JSON portion (find first '}' that closes the KED)
    const jsonEnd = kel.lastIndexOf('}') + 1;
    const jsonPart = kel.slice(0, jsonEnd);
    const attachPart = kel.slice(jsonEnd);

    // Parse the JSON body
    const parsed = JSON.parse(jsonPart);
    expect(parsed.t).toBe('icp');
    expect(parsed.i).toBe(witness.prefix);
    // For basic prefix: i is the B-code verfer, d is the SAID — they differ
    expect(parsed.i[0]).toBe('B');
    expect(parsed.d[0]).toBe('E');
    expect(parsed.i).not.toBe(parsed.d);

    // Attachment: -A counter (4 chars) + 88-char indexed sig = 92 chars
    expect(attachPart.length).toBe(92);
    expect(attachPart.startsWith('-A')).toBe(true);
  });

  it('getKel returns stored events', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );

    // Submit a controller inception
    const ctrlSigner = await Signer.generate();
    const ctrlSerder = incept({
      keys: [ctrlSigner.verfer.qb64],
      nextDigests: [],
      nextThreshold: '0',
    });
    const sigRaw = await ctrlSigner.sign(ctrlSerder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });
    const cesr = buildCesr(ctrlSerder, [siger]);
    await witness.processEvent(cesr);

    // Retrieve the KEL
    const kel = await witness.getKel(ctrlSerder.pre);
    expect(kel).not.toBeNull();
    expect(kel!.length).toBeGreaterThan(0);

    // Should contain the inception event JSON
    const parsed = JSON.parse(kel!);
    expect(parsed.t).toBe('icp');
    expect(parsed.i).toBe(ctrlSerder.pre);
  });

  it('getKel returns null for unknown prefix', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );
    const kel = await witness.getKel('Eunknown_prefix_that_does_not_exist');
    expect(kel).toBeNull();
  });

  it('processEvent returns error for unparseable data', async () => {
    const witness = await KerizonWitness.create(
      { name: 'wit0', httpPort: 5632, tcpPort: 5633 },
      store,
    );
    const garbage = new TextEncoder().encode('not valid cesr at all');
    const result = await witness.processEvent(garbage);
    expect('error' in result).toBe(true);
  });
});
