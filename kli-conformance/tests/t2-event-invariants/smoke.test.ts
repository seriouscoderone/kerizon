/**
 * Smoke test: verify the kli adapter works against a real kli installation.
 * Skips if kli is not available.
 *
 * Tests the basic lifecycle: init → incept → status → rotate → interact → export
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let adapter: KliAdapter;
const KEYSTORE_NAME = `smoke-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  adapter = new KliAdapter({
    keystoreName: KEYSTORE_NAME,
    timeout: 30_000,
  });
});

describe('kli smoke test', () => {
  it.skipIf(!KLI_AVAILABLE)('init creates a keystore', async () => {
    const result = await adapter.init({
      name: KEYSTORE_NAME,
      nopasscode: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('KERI Keystore created at');
  });

  it.skipIf(!KLI_AVAILABLE)('incept creates an identifier', async () => {
    const result = await adapter.incept({
      alias: 'smoke-test',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
    });
    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    expect(result.prefix!.length).toBe(44); // CESR-encoded AID
  });

  it.skipIf(!KLI_AVAILABLE)('status returns key state', async () => {
    const result = await adapter.status('smoke-test');
    expect(result.exitCode).toBe(0);
    expect(result.keyState).toBeTruthy();
    expect(result.keyState!.prefix).toBeTruthy();
    expect(result.keyState!.sn).toBe(0);
    expect(result.keyState!.currentKeys.length).toBeGreaterThan(0);
  });

  it.skipIf(!KLI_AVAILABLE)('rotate increments sequence number', async () => {
    const result = await adapter.rotate({ alias: 'smoke-test' });
    expect(result.exitCode).toBe(0);

    const status = await adapter.status('smoke-test');
    expect(status.keyState!.sn).toBe(1);
  });

  it.skipIf(!KLI_AVAILABLE)('interact increments sequence number', async () => {
    const result = await adapter.interact({
      alias: 'smoke-test',
      data: [{ i: 'ETest', s: '0', d: 'ETest' }],
    });
    expect(result.exitCode).toBe(0);

    const status = await adapter.status('smoke-test');
    expect(status.keyState!.sn).toBe(2);
  });

  it.skipIf(!KLI_AVAILABLE)('sign produces signatures', async () => {
    const result = await adapter.sign('smoke-test', 'hello world');
    expect(result.exitCode).toBe(0);
    expect(result.signatures).toBeTruthy();
    expect(result.signatures!.length).toBeGreaterThan(0);
  });

  it.skipIf(!KLI_AVAILABLE)('export produces CESR bytes', async () => {
    const result = await adapter.exportKel('smoke-test');
    expect(result.exitCode).toBe(0);
    expect(result.cesr).toBeTruthy();
    expect(result.cesr!.length).toBeGreaterThan(0);
  });

  it.skipIf(!KLI_AVAILABLE)('exportEvents returns parsed events', async () => {
    const result = await adapter.exportEvents('smoke-test');
    expect(result.exitCode).toBe(0);
    expect(result.events).toBeTruthy();
    // Should have icp + rot + ixn = 3 events
    expect(result.events!.length).toBe(3);
    expect(result.events![0].type).toBe('icp');
    expect(result.events![0].sn).toBe(0);
    expect(result.events![1].type).toBe('rot');
    expect(result.events![1].sn).toBe(1);
    expect(result.events![2].type).toBe('ixn');
    expect(result.events![2].sn).toBe(2);
  });
});
