import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NedbPersistence } from '@kerizon/store-nedb';

describe('NedbStore (via @kerizon/store-nedb)', () => {
  const dirs: string[] = [];
  let store: NedbPersistence;

  beforeEach(async () => {
    const dbDir = mkdtempSync(join(tmpdir(), 'nedb-store-test-'));
    dirs.push(dbDir);
    store = await NedbPersistence.create(dbDir);
  });

  afterAll(() => {
    for (const d of dirs) {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it('putEvent + getEvents returns stored event', async () => {
    await store.putEvent('Eprefix1', 0, 'Esaid1', '{"t":"icp"}', ['AAsig1']);
    const events = await store.getEvents('Eprefix1');
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({
      sn: 0,
      said: 'Esaid1',
      raw: '{"t":"icp"}',
      sigs: ['AAsig1'],
    });
  });

  it('getEvents returns empty for unknown prefix', async () => {
    const events = await store.getEvents('Eunknown');
    expect(events).toEqual([]);
  });

  it('putKeyState + getKeyState round-trips', async () => {
    const state = {
      sn: 0,
      prefix: 'EpfxABC',
      currentKeys: ['Dkey1'],
      signingThreshold: '1',
      nextDigests: [],
      nextThreshold: '0',
      witnesses: [],
      witnessThreshold: 0,
      configTraits: [],
      transferable: true,
      lastEstSn: 0,
      lastEstSaid: 'Esaid0',
    };
    await store.putKeyState('EpfxABC', state);
    const loaded = await store.getKeyState('EpfxABC');
    expect(loaded).toEqual(state);
  });

  it('getKeyState returns null for unknown prefix', async () => {
    const loaded = await store.getKeyState('Eunknown');
    expect(loaded).toBeNull();
  });

  it('putReceipt + getReceipts', async () => {
    await store.putReceipt('Esaid1', { signerAid: 'Ewitness1', signature: 'AAsig1' });
    const receipts = await store.getReceipts('Esaid1');
    expect(receipts).toHaveLength(1);
    expect(receipts[0]).toEqual({ signerAid: 'Ewitness1', signature: 'AAsig1' });
  });

  it('getReceipts returns empty for unknown said', async () => {
    const receipts = await store.getReceipts('Eunknown');
    expect(receipts).toEqual([]);
  });

  it('putWitnessIdentity + getWitnessIdentity', async () => {
    await store.putWitnessIdentity('AsignerQb64', 'Ewitness_prefix');
    const identity = await store.getWitnessIdentity();
    expect(identity).toEqual({ signerQb64: 'AsignerQb64', prefix: 'Ewitness_prefix' });
  });

  it('getWitnessIdentity returns null when empty', async () => {
    const identity = await store.getWitnessIdentity();
    expect(identity).toBeNull();
  });

  it('events ordered by sn', async () => {
    await store.putEvent('Epfx', 2, 'Esaid3', '{"s":"2"}', ['AAsig3']);
    await store.putEvent('Epfx', 0, 'Esaid1', '{"s":"0"}', ['AAsig1']);
    await store.putEvent('Epfx', 1, 'Esaid2', '{"s":"1"}', ['AAsig2']);

    const events = await store.getEvents('Epfx');
    expect(events).toHaveLength(3);
    expect(events[0].sn).toBe(0);
    expect(events[1].sn).toBe(1);
    expect(events[2].sn).toBe(2);
  });

  it('multiple events for same prefix', async () => {
    await store.putEvent('Epfx', 0, 'Esaid1', '{"s":"0"}', ['AAsig1']);
    await store.putEvent('Epfx', 1, 'Esaid2', '{"s":"1"}', ['AAsig2']);

    const events = await store.getEvents('Epfx');
    expect(events).toHaveLength(2);
    expect(events[0].said).toBe('Esaid1');
    expect(events[1].said).toBe('Esaid2');
  });

  it('putKeyState upserts on same prefix', async () => {
    const base = {
      prefix: 'Epfx',
      currentKeys: ['Dkey1'],
      signingThreshold: '1',
      nextDigests: [],
      nextThreshold: '0',
      witnesses: [],
      witnessThreshold: 0,
      configTraits: [],
      transferable: true,
      lastEstSn: 0,
      lastEstSaid: 'Esaid0',
    };
    await store.putKeyState('Epfx', { ...base, sn: 0 });
    await store.putKeyState('Epfx', { ...base, sn: 1 });
    const loaded = await store.getKeyState('Epfx');
    expect(loaded!.sn).toBe(1);
  });

  it('putWitnessIdentity upserts', async () => {
    await store.putWitnessIdentity('Asigner1', 'Eprefix1');
    await store.putWitnessIdentity('Asigner2', 'Eprefix2');
    const identity = await store.getWitnessIdentity();
    expect(identity).toEqual({ signerQb64: 'Asigner2', prefix: 'Eprefix2' });
  });
});
