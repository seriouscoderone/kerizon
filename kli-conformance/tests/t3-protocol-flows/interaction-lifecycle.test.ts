/**
 * Interaction lifecycle: incept → interact with data → verify anchoring.
 * Requires kli.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let adapter: KliAdapter;
const KS = `lifecycle-ixn-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;
  adapter = new KliAdapter({ keystoreName: KS });
  await adapter.init({ name: KS, nopasscode: true });
  await adapter.incept({ alias: 'interactor', transferable: true });
});

describe.skipIf(!KLI_AVAILABLE)('interaction lifecycle', () => {
  it('interaction does not change keys', async () => {
    const before = await adapter.status('interactor');
    const keysBefore = before.keyState!.currentKeys;

    const r = await adapter.interact({ alias: 'interactor' });
    expect(r.exitCode).toBe(0);

    const after = await adapter.status('interactor');
    expect(after.keyState!.currentKeys).toEqual(keysBefore);
  });

  it('interaction increments sn', async () => {
    const before = await adapter.status('interactor');
    const snBefore = before.keyState!.sn;

    await adapter.interact({ alias: 'interactor' });

    const after = await adapter.status('interactor');
    expect(after.keyState!.sn).toBe(snBefore + 1);
  });

  it('establishment-only identifier rejects interaction', async () => {
    await adapter.incept({
      alias: 'est-only',
      transferable: true,
      establishmentOnly: true,
    });

    const r = await adapter.interact({ alias: 'est-only' });
    expect(r.exitCode).not.toBe(0);
  });

  it('mixed rotate + interact maintains sn ordering', async () => {
    await adapter.rotate({ alias: 'interactor' });
    await adapter.interact({ alias: 'interactor' });
    await adapter.interact({ alias: 'interactor' });
    await adapter.rotate({ alias: 'interactor' });

    const result = await adapter.exportEvents('interactor');
    expect(result.events).toBeTruthy();

    for (let i = 0; i < result.events!.length; i++) {
      expect(result.events![i].sn).toBe(i);
    }
  });
});
