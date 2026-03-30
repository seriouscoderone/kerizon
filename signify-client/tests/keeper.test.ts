import { describe, it, expect } from 'vitest';
import { SimpleKeeper } from '../src/keeper.js';

describe('SimpleKeeper', () => {
  it('create produces keeper with prefix', async () => {
    const keeper = await SimpleKeeper.create();
    expect(keeper.prefix).toBeDefined();
    expect(typeof keeper.prefix).toBe('string');
    expect(keeper.prefix.length).toBeGreaterThan(0);
  });

  it('sign returns signatures', async () => {
    const keeper = await SimpleKeeper.create();
    const data = new TextEncoder().encode('hello world');
    const sigs = await keeper.sign(data);

    expect(sigs).toHaveLength(1);
    expect(sigs[0]).toBeInstanceOf(Uint8Array);
    expect(sigs[0].length).toBe(64); // Ed25519 signature
  });

  it('rotate changes keys', async () => {
    const keeper = await SimpleKeeper.create();
    const keysBefore = keeper.currentKeys;

    await keeper.rotate();
    const keysAfter = keeper.currentKeys;

    expect(keysAfter).not.toEqual(keysBefore);
  });

  it('currentKeys are Ed25519 (D prefix)', async () => {
    const keeper = await SimpleKeeper.create();
    const keys = keeper.currentKeys;

    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^D/); // Ed25519 qb64 code
  });

  it('nextKeyDigests are Blake3 (E prefix)', async () => {
    const keeper = await SimpleKeeper.create();
    const digests = keeper.nextKeyDigests;

    expect(digests).toHaveLength(1);
    expect(digests[0]).toMatch(/^E/); // Blake3-256 qb64 code
  });

  it('tier defaults to low', async () => {
    const keeper = await SimpleKeeper.create();
    expect(keeper.tier).toBe('low');
  });

  it('deriveKey returns bytes', async () => {
    const keeper = await SimpleKeeper.create();
    const key = await keeper.deriveKey('/0');

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32); // Blake3-256 output
  });
});
