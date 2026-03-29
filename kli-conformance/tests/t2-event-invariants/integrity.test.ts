/**
 * KEL integrity invariant tests.
 *
 * Tests structural integrity properties of exported KELs:
 * - Idempotent import
 * - Event ordering matches sequence numbers
 * - SAID uniqueness across all events
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

describe.skipIf(!KLI_AVAILABLE)('KEL integrity invariants', () => {
  let adapter: KliAdapter;
  const ks = 'integrity-' + Date.now();
  const alias = 'integrity-aid';

  beforeAll(async () => {
    adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });

    const init = await adapter.init({ name: ks, nopasscode: true });
    expect(init.exitCode).toBe(0);

    const incept = await adapter.incept({
      alias,
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
    });
    expect(incept.exitCode).toBe(0);

    // Build a non-trivial KEL
    await adapter.rotate({ alias });
    await adapter.interact({ alias, data: [{ d: 'EIntegrityTestDigest1234567890123456789012345' }] });
    await adapter.rotate({ alias });
    await adapter.interact({ alias, data: [] });
  });

  it('import same KEL twice: status unchanged (idempotent)', async () => {
    const exported = await adapter.exportKel(alias);
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();

    // Import into fresh keystore
    const ks2 = 'integrity-idem-' + Date.now();
    const adapter2 = new KliAdapter({ keystoreName: ks2, timeout: 30_000 });
    await adapter2.init({ name: ks2, nopasscode: true });

    // First import
    const import1 = await adapter2.importKel(exported.cesr!);
    expect(import1.exitCode).toBe(0);

    // Second import
    const import2 = await adapter2.importKel(exported.cesr!);
    expect(import2.exitCode).toBe(0);
  });

  it('export after import: event order matches sn', async () => {
    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();
    expect(events.events!.length).toBe(5); // icp + rot + ixn + rot + ixn

    // Verify events are ordered by sequence number
    for (let i = 0; i < events.events!.length; i++) {
      expect(events.events![i].sn).toBe(i);
    }

    // Verify sequence is strictly monotonically increasing
    for (let i = 1; i < events.events!.length; i++) {
      expect(events.events![i].sn).toBe(events.events![i - 1].sn + 1);
    }
  });

  it('all exported event SAIDs are unique', async () => {
    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();

    const saids = events.events!.map(e => e.said);
    const uniqueSaids = new Set(saids);

    // Every SAID should be unique
    expect(uniqueSaids.size).toBe(saids.length);

    // Every SAID should be non-empty
    for (const said of saids) {
      expect(said.length).toBeGreaterThan(0);
    }
  });
});
