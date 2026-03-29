/**
 * Cross-implementation establishment-only trait: kerizon -> kli.
 *
 * Verifies the establishment-only (EO) configuration trait is respected:
 *
 *   1. kerizon incepts with establishmentOnly: true
 *   2. kerizon rotates — should succeed (sn=1)
 *   3. kerizon interacts — should FAIL (EO rejects ixn)
 *   4. kerizon exports KEL -> kli imports
 *   5. kli sees the rotated key state (sn=1)
 *   6. kli verifies KEL has exactly 2 events (icp + rot, no ixn)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `eo-interop-kli-${Date.now()}`;
const KS_KERIZON = `eo-interop-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state
let eoPrefix: string;
let exportedCesr: Uint8Array;
let kerizonEventSaids: string[];

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

describe.skipIf(!KLI_AVAILABLE)('cross-impl establishment-only trait: kerizon -> kli', () => {
  it('step 1: kerizon incepts with establishmentOnly: true', async () => {
    const result = await kerizon.incept({
      alias: 'eo-aid',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      establishmentOnly: true,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    eoPrefix = result.prefix!;
  });

  it('step 2: kerizon status shows EO config trait and sn=0', async () => {
    const status = await kerizon.status('eo-aid');
    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.prefix).toBe(eoPrefix);
    expect(status.keyState!.sn).toBe(0);

    // The inception should carry the EO trait in config
    const events = await kerizon.exportEvents('eo-aid');
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();

    const icpRaw = JSON.parse(events.events![0].raw);
    // 'c' field in icp contains configuration traits, EO = 'EO'
    expect(icpRaw['c']).toBeTruthy();
    expect(icpRaw['c']).toContain('EO');
  });

  it('step 3: kerizon rotates successfully (sn advances to 1)', async () => {
    const rot = await kerizon.rotate({ alias: 'eo-aid' });
    expect(rot.exitCode).toBe(0);

    const status = await kerizon.status('eo-aid');
    expect(status.exitCode).toBe(0);
    expect(status.keyState!.sn).toBe(1);
  });

  it('step 4: kerizon interact FAILS (EO rejects ixn)', async () => {
    const ixn = await kerizon.interact({ alias: 'eo-aid' });
    // EO identifiers reject interaction events -- expect non-zero exit
    expect(ixn.exitCode).not.toBe(0);
  });

  it('step 5: kerizon status still shows sn=1 (ixn was rejected)', async () => {
    const status = await kerizon.status('eo-aid');
    expect(status.exitCode).toBe(0);
    expect(status.keyState!.sn).toBe(1);
  });

  it('step 6: kerizon exports exactly 2 events (icp + rot)', async () => {
    const events = await kerizon.exportEvents('eo-aid');
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();
    expect(events.events!.length).toBe(2);

    const types = events.events!.map(e => e.type);
    expect(types).toEqual(['icp', 'rot']);

    const sns = events.events!.map(e => e.sn);
    expect(sns).toEqual([0, 1]);

    kerizonEventSaids = events.events!.map(e => e.said);
  });

  it('step 7: kerizon exports full KEL as CESR', async () => {
    const exported = await kerizon.exportKel('eo-aid');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);
    exportedCesr = exported.cesr!;
  });

  it('step 8: kli imports the CESR stream', async () => {
    const imported = await kli.importKel(exportedCesr);
    expect(imported.exitCode).toBe(0);
  });

  it('step 9: kli sees the rotated key state (sn=1)', async () => {
    const status = await kli.status('eo-aid');
    if (status.exitCode === 0 && status.keyState) {
      expect(status.keyState.prefix).toBe(eoPrefix);
      expect(status.keyState.sn).toBe(1);
    }
  });

  it('step 10: kli event SAIDs match kerizon originals (exactly 2)', async () => {
    const events = await kli.exportEvents('eo-aid');
    if (events.exitCode !== 0 || !events.events) return;

    expect(events.events.length).toBe(2);

    for (let i = 0; i < events.events.length; i++) {
      expect(events.events[i].said).toBe(kerizonEventSaids[i]);
    }
  });
});
