/**
 * Anchoring invariant tests.
 *
 * Tests that interaction events correctly anchor data seals
 * and that the exported event structure matches KERI spec field ordering.
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import { IXN_FIELD_ORDER } from '../../src/generators/events.js';

describe.skipIf(!KLI_AVAILABLE)('anchoring invariants', () => {
  let adapter: KliAdapter;
  const ks = 'anchoring-' + Date.now();
  const alias = 'anchor-aid';

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
  });

  it('interact with digest seal: exported event "a" field contains the seal', async () => {
    const digestSeal = { d: 'EBfxc4RiVY6saIFmUfEtU99o2Gftqr4qOhATQPHMFrmR' };

    const ixn = await adapter.interact({
      alias,
      data: [digestSeal],
    });
    expect(ixn.exitCode).toBe(0);

    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);

    // The interaction event is the last event (after icp)
    const ixnEvents = events.events!.filter(e => e.type === 'ixn');
    expect(ixnEvents.length).toBeGreaterThan(0);

    const lastIxn = ixnEvents[ixnEvents.length - 1];
    const parsed = JSON.parse(lastIxn.raw);
    const anchors = parsed['a'] as Array<Record<string, unknown>>;
    expect(anchors).toBeTruthy();
    expect(anchors.length).toBeGreaterThan(0);
    expect(anchors[0]['d']).toBe(digestSeal.d);
  });

  it('interact with event seal: exported event "a" field contains {i, s, d}', async () => {
    const eventSeal = {
      i: 'EBfxc4RiVY6saIFmUfEtU99o2Gftqr4qOhATQPHMFrmR',
      s: '0',
      d: 'EBfxc4RiVY6saIFmUfEtU99o2Gftqr4qOhATQPHMFrmR',
    };

    const ixn = await adapter.interact({
      alias,
      data: [eventSeal],
    });
    expect(ixn.exitCode).toBe(0);

    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);

    const ixnEvents = events.events!.filter(e => e.type === 'ixn');
    const lastIxn = ixnEvents[ixnEvents.length - 1];
    const parsed = JSON.parse(lastIxn.raw);
    const anchors = parsed['a'] as Array<Record<string, unknown>>;
    expect(anchors).toBeTruthy();
    expect(anchors.length).toBeGreaterThan(0);
    expect(anchors[0]['i']).toBe(eventSeal.i);
    expect(anchors[0]['s']).toBe(eventSeal.s);
    expect(anchors[0]['d']).toBe(eventSeal.d);
  });

  it('interact with empty data: exported event has empty "a" list', async () => {
    const ixn = await adapter.interact({
      alias,
      data: [],
    });
    expect(ixn.exitCode).toBe(0);

    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);

    const ixnEvents = events.events!.filter(e => e.type === 'ixn');
    const lastIxn = ixnEvents[ixnEvents.length - 1];
    const parsed = JSON.parse(lastIxn.raw);
    const anchors = parsed['a'] as unknown[];
    expect(anchors).toEqual([]);
  });

  it('interaction field order: v, t, d, i, s, p, a', async () => {
    const ixn = await adapter.interact({
      alias,
      data: [{ d: 'EFieldOrderTestDigest123456789012345678901234' }],
    });
    expect(ixn.exitCode).toBe(0);

    const events = await adapter.exportEvents(alias);
    expect(events.exitCode).toBe(0);

    const ixnEvents = events.events!.filter(e => e.type === 'ixn');
    const lastIxn = ixnEvents[ixnEvents.length - 1];
    const parsed = JSON.parse(lastIxn.raw);

    // Verify field order matches IXN_FIELD_ORDER: v, t, d, i, s, p, a
    const keys = Object.keys(parsed);
    const expectedOrder = [...IXN_FIELD_ORDER];

    // Check that each expected field appears in order
    let lastIdx = -1;
    for (const field of expectedOrder) {
      const idx = keys.indexOf(field);
      expect(idx).toBeGreaterThan(lastIdx);
      lastIdx = idx;
    }
  });
});
