import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryPersistence } from '../../src/persistence/memory.js';
import type { SerializedKeyState } from '../../src/persistence/types.js';

describe('MemoryPersistence', () => {
  let store: MemoryPersistence;

  beforeEach(() => {
    store = new MemoryPersistence();
  });

  // ── KEL Events ──

  describe('events', () => {
    it('putEvent + getEvents returns events sorted by sn', async () => {
      await store.putEvent('pre1', 1, 'said1', '{"t":"ixn"}', ['sig1']);
      await store.putEvent('pre1', 0, 'said0', '{"t":"icp"}', ['sig0']);

      const events = await store.getEvents('pre1');
      expect(events).toHaveLength(2);
      expect(events[0].sn).toBe(0);
      expect(events[1].sn).toBe(1);
    });

    it('getEvents returns empty array for unknown prefix', async () => {
      const events = await store.getEvents('unknown');
      expect(events).toEqual([]);
    });

    it('getEvent returns single event by sn', async () => {
      await store.putEvent('pre1', 0, 'said0', '{"t":"icp"}', ['sig0']);
      await store.putEvent('pre1', 1, 'said1', '{"t":"ixn"}', ['sig1']);

      const evt = await store.getEvent('pre1', 1);
      expect(evt).toEqual({ said: 'said1', raw: '{"t":"ixn"}', sigs: ['sig1'] });
    });

    it('getEvent returns null for missing sn', async () => {
      await store.putEvent('pre1', 0, 'said0', '{"t":"icp"}', ['sig0']);
      expect(await store.getEvent('pre1', 5)).toBeNull();
    });

    it('getEvent returns null for unknown prefix', async () => {
      expect(await store.getEvent('unknown', 0)).toBeNull();
    });

    it('events for different prefixes are isolated', async () => {
      await store.putEvent('pre1', 0, 'said0', 'raw0', ['sig0']);
      await store.putEvent('pre2', 0, 'saidX', 'rawX', ['sigX']);

      expect(await store.getEvents('pre1')).toHaveLength(1);
      expect(await store.getEvents('pre2')).toHaveLength(1);
      expect((await store.getEvents('pre1'))[0].said).toBe('said0');
      expect((await store.getEvents('pre2'))[0].said).toBe('saidX');
    });
  });

  // ── Key State ──

  describe('keyState', () => {
    const sampleState: SerializedKeyState = {
      prefix: 'Epre1',
      sn: 2,
      currentKeys: ['Dkey1'],
      signingThreshold: '1',
      nextDigests: ['Edig1'],
      nextThreshold: '1',
      witnesses: [],
      witnessThreshold: 0,
      configTraits: [],
      transferable: true,
      lastEstSn: 2,
      lastEstSaid: 'Esaid2',
    };

    it('putKeyState + getKeyState round-trips', async () => {
      await store.putKeyState('pre1', sampleState);
      expect(await store.getKeyState('pre1')).toEqual(sampleState);
    });

    it('getKeyState returns null for unknown prefix', async () => {
      expect(await store.getKeyState('unknown')).toBeNull();
    });

    it('putKeyState overwrites previous state', async () => {
      await store.putKeyState('pre1', sampleState);
      const updated = { ...sampleState, sn: 3 };
      await store.putKeyState('pre1', updated);
      expect((await store.getKeyState('pre1'))!.sn).toBe(3);
    });
  });

  // ── Aliases ──

  describe('aliases', () => {
    it('putAlias + getPrefix round-trips', async () => {
      await store.putAlias('alice', 'Epre1');
      expect(await store.getPrefix('alice')).toBe('Epre1');
    });

    it('getPrefix returns null for unknown alias', async () => {
      expect(await store.getPrefix('nobody')).toBeNull();
    });

    it('listAliases returns all aliases', async () => {
      await store.putAlias('alice', 'Epre1');
      await store.putAlias('bob', 'Epre2');

      const list = await store.listAliases();
      expect(list).toHaveLength(2);
      expect(list).toContainEqual({ alias: 'alice', prefix: 'Epre1' });
      expect(list).toContainEqual({ alias: 'bob', prefix: 'Epre2' });
    });

    it('listAliases returns empty array when none exist', async () => {
      expect(await store.listAliases()).toEqual([]);
    });
  });

  // ── Signing Keys ──

  describe('signers', () => {
    const signerData = { alias: 'alice', currentQb64s: ['Akey1'], nextQb64s: ['Akey2'] };

    it('putSigners + getSigners round-trips', async () => {
      await store.putSigners('pre1', signerData);
      expect(await store.getSigners('pre1')).toEqual(signerData);
    });

    it('getSigners returns null for unknown prefix', async () => {
      expect(await store.getSigners('unknown')).toBeNull();
    });
  });

  // ── Receipts ──

  describe('receipts', () => {
    it('putReceipt + getReceipts accumulates', async () => {
      await store.putReceipt('said1', { signerAid: 'wit1', signature: 'sig1' });
      await store.putReceipt('said1', { signerAid: 'wit2', signature: 'sig2' });

      const receipts = await store.getReceipts('said1');
      expect(receipts).toHaveLength(2);
      expect(receipts[0]).toEqual({ signerAid: 'wit1', signature: 'sig1' });
      expect(receipts[1]).toEqual({ signerAid: 'wit2', signature: 'sig2' });
    });

    it('getReceipts returns empty array for unknown said', async () => {
      expect(await store.getReceipts('unknown')).toEqual([]);
    });
  });

  // ── Registries ──

  describe('registries', () => {
    const regData = { said: 'Ereg1', name: 'vLEI', lastSaid: 'Elast', lastSn: 0 };

    it('putRegistry + getRegistry round-trips', async () => {
      await store.putRegistry('vLEI', regData);
      expect(await store.getRegistry('vLEI')).toEqual(regData);
    });

    it('getRegistry returns null for unknown name', async () => {
      expect(await store.getRegistry('unknown')).toBeNull();
    });

    it('listRegistries returns all registries', async () => {
      await store.putRegistry('vLEI', regData);
      await store.putRegistry('other', { said: 'Ereg2', name: 'other', lastSaid: 'Elast2', lastSn: 0 });

      const list = await store.listRegistries();
      expect(list).toHaveLength(2);
      expect(list).toContainEqual({ said: 'Ereg1', name: 'vLEI' });
      expect(list).toContainEqual({ said: 'Ereg2', name: 'other' });
    });
  });

  // ── Credentials ──

  describe('credentials', () => {
    const credData = { said: 'Ecred1', registrySaid: 'Ereg1', state: 'issued', raw: '{}' };

    it('putCredential + getCredential round-trips', async () => {
      await store.putCredential('Ecred1', credData);
      expect(await store.getCredential('Ecred1')).toEqual(credData);
    });

    it('getCredential returns null for unknown said', async () => {
      expect(await store.getCredential('unknown')).toBeNull();
    });

    it('listCredentials returns all credentials', async () => {
      await store.putCredential('Ecred1', credData);
      await store.putCredential('Ecred2', { said: 'Ecred2', registrySaid: 'Ereg1', state: 'revoked', raw: '{}' });

      const list = await store.listCredentials();
      expect(list).toHaveLength(2);
      expect(list).toContainEqual({ said: 'Ecred1', state: 'issued' });
      expect(list).toContainEqual({ said: 'Ecred2', state: 'revoked' });
    });
  });

  // ── Endpoints ──

  describe('endpoints', () => {
    it('putEndpoint + getEndpoint round-trips', async () => {
      await store.putEndpoint('Eaid1', 'http://localhost:5555');
      expect(await store.getEndpoint('Eaid1')).toBe('http://localhost:5555');
    });

    it('getEndpoint returns null for unknown aid', async () => {
      expect(await store.getEndpoint('unknown')).toBeNull();
    });
  });

  // ── Witness Identity ──

  describe('witnessIdentity', () => {
    it('putWitnessIdentity + getWitnessIdentity round-trips', async () => {
      await store.putWitnessIdentity('Asigner', 'Bprefix');
      expect(await store.getWitnessIdentity()).toEqual({ signerQb64: 'Asigner', prefix: 'Bprefix' });
    });

    it('getWitnessIdentity returns null before any put', async () => {
      expect(await store.getWitnessIdentity()).toBeNull();
    });

    it('putWitnessIdentity overwrites previous identity', async () => {
      await store.putWitnessIdentity('Asigner1', 'Bprefix1');
      await store.putWitnessIdentity('Asigner2', 'Bprefix2');
      expect(await store.getWitnessIdentity()).toEqual({ signerQb64: 'Asigner2', prefix: 'Bprefix2' });
    });
  });

  // ── Lifecycle ──

  describe('close', () => {
    it('close resolves without error', async () => {
      await expect(store.close()).resolves.toBeUndefined();
    });
  });
});
