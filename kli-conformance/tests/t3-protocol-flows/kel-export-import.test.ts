/**
 * KEL export/import round-trip: export CESR → import into fresh keystore → verify.
 * Requires kli.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let adapterA: KliAdapter;
let adapterB: KliAdapter;

const KS_A = `exporter-${Date.now()}`;
const KS_B = `importer-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  adapterA = new KliAdapter({ keystoreName: KS_A });
  adapterB = new KliAdapter({ keystoreName: KS_B });

  await adapterA.init({ name: KS_A, nopasscode: true });
  await adapterB.init({ name: KS_B, nopasscode: true });
});

describe.skipIf(!KLI_AVAILABLE)('KEL export/import round-trip', () => {
  it('exported CESR imports into a fresh keystore', async () => {
    // Build a KEL: incept + rotate + interact
    await adapterA.incept({ alias: 'roundtrip', transferable: true });
    await adapterA.rotate({ alias: 'roundtrip' });
    await adapterA.interact({ alias: 'roundtrip' });

    // Export
    const exported = await adapterA.exportKel('roundtrip');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);

    // Import into fresh keystore
    const imported = await adapterB.importKel(exported.cesr!);
    expect(imported.exitCode).toBe(0);
  });

  it('sign on A, verify on B after import', async () => {
    const text = 'cross-keystore verification test';

    // Sign with A
    const signed = await adapterA.sign('roundtrip', text);
    expect(signed.exitCode).toBe(0);
    expect(signed.signatures).toBeTruthy();

    // Get A's prefix
    const statusA = await adapterA.status('roundtrip');
    const prefix = statusA.keyState!.prefix;

    // Verify on B
    const verified = await adapterB.verify(prefix, text, signed.signatures!);
    expect(verified.valid).toBe(true);
  });
});
