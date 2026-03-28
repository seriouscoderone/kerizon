/**
 * OOBI discovery: generate OOBI → resolve from another keystore.
 * Requires kli + witness demo running.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { KliAdapter, DEMO_WITNESSES } from '../../src/adapter/kli-adapter.js';
import type { WitnessHandle } from '../../src/adapter/types.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let witnessesRunning = false;
let adapterA: KliAdapter;
let adapterB: KliAdapter;
let witnesses: WitnessHandle | undefined;

const KS_A = `oobi-a-${Date.now()}`;
const KS_B = `oobi-b-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  adapterA = new KliAdapter({ keystoreName: KS_A, timeout: 60_000 });
  adapterB = new KliAdapter({ keystoreName: KS_B, timeout: 60_000 });
  await adapterA.init({ name: KS_A, nopasscode: true });
  await adapterB.init({ name: KS_B, nopasscode: true });

  // Try to start witnesses
  try {
    witnesses = await adapterA.witnessDemo();
    witnessesRunning = true;
  } catch {
    witnessesRunning = false;
  }
});

afterAll(async () => {
  if (witnesses) await witnesses.stop();
});

describe.skipIf(!KLI_AVAILABLE || !witnessesRunning)('OOBI discovery with witnesses', () => {
  it('resolve witness OOBIs', async () => {
    // Resolve wan witness OOBI on keystore A
    const wan = DEMO_WITNESSES.wan;
    const oobiUrl = `http://127.0.0.1:${wan.http}/oobi/${wan.aid}/controller`;
    const result = await adapterA.oobiResolve(oobiUrl, 'wan');
    expect(result.exitCode).toBe(0);
  });

  it('incept with witnesses and generate OOBI', async () => {
    // Resolve witness OOBIs on both
    for (const [name, w] of Object.entries(DEMO_WITNESSES).slice(0, 3)) {
      const url = `http://127.0.0.1:${w.http}/oobi/${w.aid}/controller`;
      await adapterA.oobiResolve(url, name);
      await adapterB.oobiResolve(url, name);
    }

    // Incept on A with witnesses
    const [wan, wil, wes] = Object.values(DEMO_WITNESSES).slice(0, 3);
    const r = await adapterA.incept({
      alias: 'oobi-test',
      transferable: true,
      witnesses: [wan.aid, wil.aid, wes.aid],
      witnessThreshold: 2,
      receiptEndpoint: true,
    });
    expect(r.exitCode).toBe(0);

    // Generate OOBI on A
    const oobi = await adapterA.oobiGenerate('oobi-test', 'witness');
    expect(oobi.exitCode).toBe(0);
    expect(oobi.oobis).toBeTruthy();
    expect(oobi.oobis!.length).toBeGreaterThan(0);

    // Resolve A's OOBI on B
    const resolve = await adapterB.oobiResolve(oobi.oobis![0], 'oobi-test');
    expect(resolve.exitCode).toBe(0);
  });
});

describe.skipIf(!KLI_AVAILABLE)('OOBI without witnesses', () => {
  it('identifier without witnesses has no witness OOBIs', async () => {
    await adapterA.incept({ alias: 'no-wit', transferable: true });
    const r = await adapterA.oobiGenerate('no-wit', 'witness');
    // Should fail or return empty since there are no witnesses
    if (r.exitCode === 0) {
      expect(r.oobis ?? []).toHaveLength(0);
    }
  });
});
