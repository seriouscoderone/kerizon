/**
 * Inception lifecycle: test full inception flow via CLI adapter.
 * Verifies: init → incept → status → event properties.
 * Requires kli.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { checkFirstSeenUniqueness, checkSaidUniqueness } from '../../src/invariants/first-seen.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let adapter: KliAdapter;
const KS = `lifecycle-icp-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;
  adapter = new KliAdapter({ keystoreName: KS });
  await adapter.init({ name: KS, nopasscode: true });
});

describe.skipIf(!KLI_AVAILABLE)('inception lifecycle', () => {
  it('creates identifier with correct initial state', async () => {
    const result = await adapter.incept({
      alias: 'alice',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
    });
    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();

    const status = await adapter.status('alice');
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.sn).toBe(0);
    expect(status.keyState!.currentKeys).toHaveLength(1);
    expect(status.keyState!.prefix).toBe(result.prefix);
  });

  it('exported events satisfy first-seen invariants', async () => {
    const result = await adapter.exportEvents('alice');
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBe(1);

    const events = result.events!.map(e => JSON.parse(e.raw));
    expect(checkFirstSeenUniqueness(events).valid).toBe(true);
    expect(checkSaidUniqueness(events).valid).toBe(true);
  });

  it('inception SAID is used as prefix (i == d)', async () => {
    const result = await adapter.exportEvents('alice');
    const icp = JSON.parse(result.events![0].raw);
    expect(icp['i']).toBe(icp['d']);
  });

  it('non-transferable inception cannot rotate', async () => {
    const r = await adapter.incept({
      alias: 'bob-nt',
      transferable: false,
      signingKeyCount: 1,
      nextKeyCount: 1,
      signingThreshold: '1',
      nextThreshold: '1',
    });
    expect(r.exitCode).toBe(0);

    const rot = await adapter.rotate({ alias: 'bob-nt' });
    expect(rot.exitCode).not.toBe(0);
  });
});
