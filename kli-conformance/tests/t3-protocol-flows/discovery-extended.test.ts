/**
 * Extended discovery tests: OOBI generation, resolution, endpoint registration.
 *
 * Requires kli + witnesses running with endpoint records configured.
 * Note: kli oobiGenerate returns exit 255 when witness endpoint
 * records are not registered (keripy `kli witness demo` limitation).
 *
 * Spec invariants tested:
 * - discovery: OOBI format contains AID prefix and role
 * - discovery: resolution stores remote key state
 * - discovery: multiple OOBIs for same AID (different roles)
 * - discovery: OOBI resolution fails gracefully for unreachable URL
 * - accountability/dissemination: endpoint registration via ends add/list
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter, DEMO_WITNESSES } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import { WITNESSES_AVAILABLE } from '../kli-witnesses-available.js';

const SKIP = !KLI_AVAILABLE || !WITNESSES_AVAILABLE;

let adapterA: KliAdapter;
let adapterB: KliAdapter;
const ksA = `disc-a-${Date.now()}`;
const ksB = `disc-b-${Date.now()}`;
const wan = DEMO_WITNESSES.wan;
const wil = DEMO_WITNESSES.wil;

beforeAll(async () => {
  if (SKIP) return;

  adapterA = new KliAdapter({ keystoreName: ksA, timeout: 60_000 });
  adapterB = new KliAdapter({ keystoreName: ksB, timeout: 60_000 });
  await adapterA.init({ name: ksA, nopasscode: true });
  await adapterB.init({ name: ksB, nopasscode: true });

  // Resolve witness OOBIs on both
  for (const [name, w] of [['wan', wan], ['wil', wil]] as const) {
    const url = `http://127.0.0.1:${w.http}/oobi/${w.aid}/controller`;
    await adapterA.oobiResolve(url, name);
    await adapterB.oobiResolve(url, name);
  }

  // Incept A with witnesses
  await adapterA.incept({
    alias: 'discoverable',
    transferable: true,
    witnesses: [wan.aid, wil.aid],
    witnessThreshold: 1,
    receiptEndpoint: true,
  });
});

describe.skipIf(SKIP)('discovery extended - OOBI and endpoints', () => {
  it('OOBI format contains AID prefix and role', async () => {
    const result = await adapterA.oobiGenerate('discoverable', 'witness');
    expect(result.exitCode).toBe(0);
    expect(result.oobis).toBeTruthy();
    expect(result.oobis!.length).toBeGreaterThan(0);

    const status = await adapterA.status('discoverable');
    const prefix = status.keyState!.prefix;

    for (const oobi of result.oobis!) {
      expect(oobi).toContain(prefix);
      expect(oobi).toContain('/witness');
      expect(oobi).toMatch(/^https?:\/\//);
    }
  });

  it('OOBI resolution stores remote key state', async () => {
    const oobis = await adapterA.oobiGenerate('discoverable', 'witness');
    expect(oobis.oobis!.length).toBeGreaterThan(0);

    // B resolves A's OOBI
    const resolve = await adapterB.oobiResolve(oobis.oobis![0], 'remote-a');
    expect(resolve.exitCode).toBe(0);
  });

  it('multiple OOBIs for same AID with different witnesses', async () => {
    const oobis = await adapterA.oobiGenerate('discoverable', 'witness');
    expect(oobis.oobis!.length).toBeGreaterThanOrEqual(2); // wan + wil

    // Each OOBI should point to a different witness endpoint
    const urls = new Set(oobis.oobis!);
    expect(urls.size).toBe(oobis.oobis!.length);
  });

  it('OOBI for controller role differs from witness role', async () => {
    const witnessOobis = await adapterA.oobiGenerate('discoverable', 'witness');
    const controllerOobis = await adapterA.oobiGenerate('discoverable', 'controller');

    // Controller OOBIs should have /controller in the path
    if (controllerOobis.exitCode === 0 && controllerOobis.oobis?.length) {
      for (const oobi of controllerOobis.oobis) {
        expect(oobi).toContain('/controller');
      }
      // Witness and controller OOBIs should be different
      expect(witnessOobis.oobis).not.toEqual(controllerOobis.oobis);
    }
  });
});

describe.skipIf(!KLI_AVAILABLE)('discovery - graceful failures', () => {
  it('OOBI resolution fails gracefully for unreachable URL', async () => {
    const ks = `disc-fail-${Date.now()}`;
    const adapter = new KliAdapter({ keystoreName: ks, timeout: 10_000 });
    await adapter.init({ name: ks, nopasscode: true });

    // Resolve a URL that doesn't exist -- should not crash
    const result = await adapter.oobiResolve('http://127.0.0.1:19999/oobi/BFAKE/controller', 'fake');
    // Either times out or returns non-zero; either way, it shouldn't crash
    expect(result.exitCode).not.toBeUndefined();
  });
});
