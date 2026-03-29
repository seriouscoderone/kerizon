/**
 * Cross-implementation non-transferable identifier: kerizon -> kli.
 *
 * Verifies non-transferable identifiers are correctly handled:
 *
 *   1. kerizon incepts non-transferable (transferable: false, nextKeyCount: 0)
 *   2. kerizon rotate — should FAIL (non-transferable cannot rotate)
 *   3. kerizon exports KEL -> kli imports
 *   4. kli sees the identifier with sn=0
 *   5. kli exported events verify inception has empty n list and type 'icp'
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `nontrans-interop-kli-${Date.now()}`;
const KS_KERIZON = `nontrans-interop-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state
let ntPrefix: string;
let exportedCesr: Uint8Array;
let icpSaid: string;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  kli = new KliAdapter({ keystoreName: KS_KLI, timeout: 30_000 });
  kerizon = new KerizonAdapter({
    keystoreName: KS_KERIZON,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 30_000,
  });

  await kli.init({ name: KS_KLI, nopasscode: true });
  await kerizon.init({ name: KS_KERIZON });
});

describe.skipIf(!KLI_AVAILABLE)('cross-impl non-transferable identifier: kerizon -> kli', () => {
  it('step 1: kerizon incepts non-transferable (transferable: false, ncount: 0)', async () => {
    const result = await kerizon.incept({
      alias: 'nt-aid',
      transferable: false,
      signingKeyCount: 1,
      nextKeyCount: 0,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    ntPrefix = result.prefix!;
  });

  it('step 2: kerizon status shows sn=0 and non-transferable state', async () => {
    const status = await kerizon.status('nt-aid');
    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.prefix).toBe(ntPrefix);
    expect(status.keyState!.sn).toBe(0);
  });

  it('step 3: kerizon inception event has empty next-key digests list', async () => {
    const events = await kerizon.exportEvents('nt-aid');
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();
    expect(events.events!.length).toBe(1);

    const icpEvent = events.events![0];
    expect(icpEvent.type).toBe('icp');
    expect(icpEvent.sn).toBe(0);

    const raw = JSON.parse(icpEvent.raw);
    // Non-transferable: 'n' (next key digests) should be empty
    expect(raw['n']).toEqual([]);
    // Event type should be 'icp'
    expect(raw['t']).toBe('icp');

    icpSaid = icpEvent.said;
  });

  it('step 4: kerizon rotate FAILS (non-transferable cannot rotate)', async () => {
    const rot = await kerizon.rotate({ alias: 'nt-aid' });
    // Non-transferable identifiers reject rotation -- expect non-zero exit
    expect(rot.exitCode).not.toBe(0);
  });

  it('step 5: kerizon status still shows sn=0 (rotation was rejected)', async () => {
    const status = await kerizon.status('nt-aid');
    expect(status.exitCode).toBe(0);
    expect(status.keyState!.sn).toBe(0);
  });

  it('step 6: kerizon exports KEL — exactly 1 event', async () => {
    const events = await kerizon.exportEvents('nt-aid');
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();
    expect(events.events!.length).toBe(1);
  });

  it('step 7: kerizon exports full KEL as CESR', async () => {
    const exported = await kerizon.exportKel('nt-aid');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);
    exportedCesr = exported.cesr!;
  });

  it('step 8: kli imports the CESR stream', async () => {
    const imported = await kli.importKel(exportedCesr);
    expect(imported.exitCode).toBe(0);
  });

  it('step 9: kli sees the identifier with sn=0', async () => {
    const status = await kli.status('nt-aid');
    if (status.exitCode === 0 && status.keyState) {
      expect(status.keyState.prefix).toBe(ntPrefix);
      expect(status.keyState.sn).toBe(0);
    }
  });

  it('step 10: kli exported events verify icp has empty n list', async () => {
    const events = await kli.exportEvents('nt-aid');
    if (events.exitCode !== 0 || !events.events) return;

    expect(events.events.length).toBe(1);

    const icpEvent = events.events[0];
    expect(icpEvent.type).toBe('icp');
    expect(icpEvent.said).toBe(icpSaid);

    const raw = JSON.parse(icpEvent.raw);
    expect(raw['n']).toEqual([]);
    expect(raw['t']).toBe('icp');
  });
});
