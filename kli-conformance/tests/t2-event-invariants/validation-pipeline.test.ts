/**
 * Validation pipeline tests.
 *
 * Tests that kli importKel correctly rejects malformed CESR events.
 * Uses crafted events with specific defects to verify rejection behavior.
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import {
  craftMalformedInception,
  serializeEvent,
  craftOrphanRotation,
} from '../../src/invariants/validation-pipeline.js';

let adapter: KliAdapter;
const ks = 'validation-pipeline-' + Date.now();

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });

  const init = await adapter.init({ name: ks, nopasscode: true });
  expect(init.exitCode).toBe(0);
});

describe.skipIf(!KLI_AVAILABLE)('validation pipeline - malformed event rejection', () => {
  it('import inception with sn != 0 is rejected', async () => {
    const malformed = craftMalformedInception({ wrongSn: 5 });
    const cesr = serializeEvent(malformed);

    const result = await adapter.importKel(cesr);
    expect(result.exitCode).not.toBe(0);
  });

  it('import event for unknown prefix that is not inception is rejected', async () => {
    // Craft a rotation event for a prefix that has never been incepted
    const unknownPrefix = 'DZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZz';
    const orphan = craftOrphanRotation(unknownPrefix);
    const cesr = serializeEvent(orphan);

    const result = await adapter.importKel(cesr);
    expect(result.exitCode).not.toBe(0);
  });

  it('import same KEL twice is idempotent', async () => {
    // Create a real identifier and export its KEL
    const alias = 'idempotent-src-' + Date.now();
    const incept = await adapter.incept({
      alias,
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
    });
    expect(incept.exitCode).toBe(0);

    const exported = await adapter.exportKel(alias);
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();

    // Import into a fresh keystore (same adapter, different keystore)
    const ks2 = 'validation-idempotent-' + Date.now();
    const adapter2 = new KliAdapter({ keystoreName: ks2, timeout: 30_000 });
    await adapter2.init({ name: ks2, nopasscode: true });

    // First import
    const import1 = await adapter2.importKel(exported.cesr!);
    expect(import1.exitCode).toBe(0);

    // Second import of the same KEL -- should succeed (idempotent)
    const import2 = await adapter2.importKel(exported.cesr!);
    expect(import2.exitCode).toBe(0);
  });

  it('import truncated CESR is rejected', async () => {
    // Create a valid inception and serialize, then truncate
    const valid = craftMalformedInception(); // no defects = structurally valid
    const cesr = serializeEvent(valid);

    // Truncate to half the size
    const truncated = cesr.slice(0, Math.floor(cesr.length / 2));

    const result = await adapter.importKel(truncated);
    expect(result.exitCode).not.toBe(0);
  });
});
