/**
 * CESR Stream invariant tests.
 *
 * Verifies that kli exportKel produces well-formed CESR streams
 * with correct self-framing, version strings, attachment ordering,
 * and count codes.
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import {
  checkStreamSelfFraming,
  checkVersionString,
  checkAttachmentOrder,
  findCountCodes,
} from '../../src/invariants/cesr-stream.js';

let adapter: KliAdapter;
const ks = 'cesr-stream-' + Date.now();

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });

  const init = await adapter.init({ name: ks, nopasscode: true });
  expect(init.exitCode).toBe(0);

  const incept = await adapter.incept({
    alias: 'cesr-stream-aid',
    transferable: true,
    signingKeyCount: 1,
    nextKeyCount: 1,
    signingThreshold: '1',
    nextThreshold: '1',
  });
  expect(incept.exitCode).toBe(0);

  // Add a rotation and interaction so the export has multiple events
  const rot = await adapter.rotate({ alias: 'cesr-stream-aid' });
  expect(rot.exitCode).toBe(0);

  const ixn = await adapter.interact({
    alias: 'cesr-stream-aid',
    data: [{ i: 'ETest', s: '0', d: 'ETest' }],
  });
  expect(ixn.exitCode).toBe(0);
});

describe.skipIf(!KLI_AVAILABLE)('CESR stream invariants', () => {
  it('export produces self-framing CESR stream', async () => {
    const result = await adapter.exportKel('cesr-stream-aid');
    expect(result.exitCode).toBe(0);
    expect(result.cesr).toBeTruthy();
    expect(result.cesr!.length).toBeGreaterThan(0);

    const check = checkStreamSelfFraming(result.cesr!);
    expect(check.violations).toEqual([]);
    expect(check.valid).toBe(true);
  });

  it('every event body has KERI version string', async () => {
    const result = await adapter.exportKel('cesr-stream-aid');
    expect(result.exitCode).toBe(0);

    const check = checkVersionString(result.cesr!);
    expect(check.violations).toEqual([]);
    expect(check.valid).toBe(true);
  });

  it('attachments follow event bodies', async () => {
    const result = await adapter.exportKel('cesr-stream-aid');
    expect(result.exitCode).toBe(0);

    const check = checkAttachmentOrder(result.cesr!);
    expect(check.violations).toEqual([]);
    expect(check.valid).toBe(true);
  });

  it('count codes present in export', async () => {
    const result = await adapter.exportKel('cesr-stream-aid');
    expect(result.exitCode).toBe(0);

    const { codes, valid, violations } = findCountCodes(result.cesr!);
    expect(violations).toEqual([]);
    expect(valid).toBe(true);
    // A KEL with 3 events should have at least 3 count codes (one per event attachment)
    expect(codes.length).toBeGreaterThanOrEqual(3);

    // Every count code must start with '-'
    for (const { code } of codes) {
      expect(code.startsWith('-')).toBe(true);
    }
  });

  it('export of non-existent alias returns error', async () => {
    const result = await adapter.exportKel('nonexistent-alias-' + Date.now());
    expect(result.exitCode).not.toBe(0);
  });
});
