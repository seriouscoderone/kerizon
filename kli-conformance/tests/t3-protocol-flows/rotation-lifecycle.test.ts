/**
 * Rotation lifecycle: incept → rotate N times → verify KEL invariants.
 * Requires kli.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { checkSequenceMonotonicity } from '../../src/invariants/sequence.js';
import { checkPreRotationChain, checkSaidIntegrity } from '../../src/invariants/pre-rotation.js';
import { checkAllFirstSeenInvariants } from '../../src/invariants/first-seen.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let adapter: KliAdapter;
const KS = `lifecycle-rot-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;
  adapter = new KliAdapter({ keystoreName: KS });
  await adapter.init({ name: KS, nopasscode: true });
  await adapter.incept({
    alias: 'rotator',
    transferable: true,
    signingKeyCount: 1,
    nextKeyCount: 1,
  });
});

describe.skipIf(!KLI_AVAILABLE)('rotation lifecycle', () => {
  it('multiple rotations maintain sn monotonicity', async () => {
    for (let i = 0; i < 3; i++) {
      const r = await adapter.rotate({ alias: 'rotator' });
      expect(r.exitCode).toBe(0);
    }

    const result = await adapter.exportEvents('rotator');
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBe(4); // icp + 3 rot

    const parsed = result.events!.map(e => ({ sn: e.sn }));
    expect(checkSequenceMonotonicity(parsed).valid).toBe(true);
  });

  it('rotation changes public keys', async () => {
    const before = await adapter.status('rotator');
    const keysBefore = before.keyState!.currentKeys;

    await adapter.rotate({ alias: 'rotator' });

    const after = await adapter.status('rotator');
    const keysAfter = after.keyState!.currentKeys;

    // Keys should have changed
    expect(keysAfter).not.toEqual(keysBefore);
  });

  it('exported KEL satisfies pre-rotation chain invariant', async () => {
    const result = await adapter.exportEvents('rotator');
    const events = result.events!.map(e => JSON.parse(e.raw));
    expect(checkPreRotationChain(events).valid).toBe(true);
  });

  it('all events have unique SAIDs', async () => {
    const result = await adapter.exportEvents('rotator');
    const events = result.events!.map(e => JSON.parse(e.raw));
    expect(checkAllFirstSeenInvariants(events).valid).toBe(true);
  });

  it('rotation with next-count changes future key count', async () => {
    const r = await adapter.rotate({ alias: 'rotator', nextKeyCount: 3, nextThreshold: '2' });
    expect(r.exitCode).toBe(0);

    // Next rotation should use 3 keys
    const r2 = await adapter.rotate({ alias: 'rotator', nextKeyCount: 1 });
    expect(r2.exitCode).toBe(0);

    const status = await adapter.status('rotator');
    expect(status.keyState!.currentKeys.length).toBe(3);
  });
});
