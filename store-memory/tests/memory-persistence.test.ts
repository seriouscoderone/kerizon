import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryPersistence } from '../src/memory-persistence.js';
import type { SerializedKeyState } from '@kerizon/keri-core';

describe('MemoryPersistence (@kerizon/store-memory)', () => {
  let store: MemoryPersistence;

  beforeEach(() => {
    store = new MemoryPersistence();
  });

  // ── 1. Events ──

  it('put/get events round-trips and sorts by sn', async () => {
    await store.putEvent('pre1', 1, 'said1', '{"t":"ixn"}', ['sig1']);
    await store.putEvent('pre1', 0, 'said0', '{"t":"icp"}', ['sig0']);

    const events = await store.getEvents('pre1');
    expect(events).toHaveLength(2);
    expect(events[0].sn).toBe(0);
    expect(events[1].sn).toBe(1);
  });

  // ── 2. Key State ──

  it('put/get key state round-trips', async () => {
    const state: SerializedKeyState = {
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

    await store.putKeyState('pre1', state);
    expect(await store.getKeyState('pre1')).toEqual(state);
    expect(await store.getKeyState('unknown')).toBeNull();
  });

  // ── 3. Aliases ──

  it('put/get/list aliases', async () => {
    await store.putAlias('alice', 'Epre1');
    await store.putAlias('bob', 'Epre2');

    expect(await store.getPrefix('alice')).toBe('Epre1');
    expect(await store.getPrefix('nobody')).toBeNull();

    const list = await store.listAliases();
    expect(list).toHaveLength(2);
    expect(list).toContainEqual({ alias: 'alice', prefix: 'Epre1' });
    expect(list).toContainEqual({ alias: 'bob', prefix: 'Epre2' });
  });

  // ── 4. Credentials ──

  it('put/get/list credentials', async () => {
    const cred = { said: 'Ecred1', registrySaid: 'Ereg1', state: 'issued', raw: '{}' };
    await store.putCredential('Ecred1', cred);

    expect(await store.getCredential('Ecred1')).toEqual(cred);
    expect(await store.getCredential('unknown')).toBeNull();

    await store.putCredential('Ecred2', { said: 'Ecred2', registrySaid: 'Ereg1', state: 'revoked', raw: '{}' });
    const list = await store.listCredentials();
    expect(list).toHaveLength(2);
  });

  // ── 5. Witness Identity + Close ──

  it('witness identity and lifecycle', async () => {
    expect(await store.getWitnessIdentity()).toBeNull();

    await store.putWitnessIdentity('Asigner', 'Bprefix');
    expect(await store.getWitnessIdentity()).toEqual({ signerQb64: 'Asigner', prefix: 'Bprefix' });

    await expect(store.close()).resolves.toBeUndefined();
  });
});
