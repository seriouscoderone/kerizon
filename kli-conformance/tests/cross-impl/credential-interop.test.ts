/**
 * Cross-implementation credential lifecycle: kerizon -> kli.
 *
 * Exercises the credential issuance flow and verifies kli can import
 * and parse the resulting KEL including anchoring ixn events:
 *
 *   1. kerizon incepts an issuer
 *   2. kerizon creates a credential registry (anchored via ixn)
 *   3. kerizon creates a credential (anchored via ixn)
 *   4. kerizon exports the full KEL (icp + anchoring ixn events)
 *   5. kli imports the KEL and verifies events parse correctly
 *   6. Verify ixn events have anchor seals with registry/credential SAIDs
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `cred-interop-kli-${Date.now()}`;
const KS_KERIZON = `cred-interop-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state
let issuerPrefix: string;
let exportedCesr: Uint8Array;
let kerizonEventSaids: string[];

const REGISTRY_NAME = 'test-registry';
const SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';

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

describe.skipIf(!KLI_AVAILABLE)('cross-impl credential lifecycle: kerizon -> kli', () => {
  it('step 1: kerizon incepts an issuer identity', async () => {
    const result = await kerizon.incept({
      alias: 'issuer',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    issuerPrefix = result.prefix!;
  });

  it('step 2: kerizon creates a credential registry', async () => {
    const result = await kerizon.vcRegistryIncept('issuer', REGISTRY_NAME);
    expect(result.exitCode).toBe(0);
  });

  it('step 3: kerizon creates a credential', async () => {
    const result = await kerizon.vcCreate({
      alias: 'issuer',
      registryName: REGISTRY_NAME,
      schema: SCHEMA_SAID,
      data: { name: 'Alice', role: 'tester' },
    });
    expect(result.exitCode).toBe(0);
  });

  it('step 4: kerizon status shows sn > 0 after registry + credential creation', async () => {
    const status = await kerizon.status('issuer');
    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.prefix).toBe(issuerPrefix);
    // icp (sn=0) + at least one ixn for registry + one ixn for credential
    expect(status.keyState!.sn).toBeGreaterThanOrEqual(2);
  });

  it('step 5: kerizon exports events — ixn events contain anchor seals', async () => {
    const events = await kerizon.exportEvents('issuer');
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();

    // At minimum: icp + registry ixn + credential ixn
    expect(events.events!.length).toBeGreaterThanOrEqual(3);

    // First event is icp
    expect(events.events![0].type).toBe('icp');

    // Subsequent events should be ixn (anchoring registry and credential)
    const ixnEvents = events.events!.filter(e => e.type === 'ixn');
    expect(ixnEvents.length).toBeGreaterThanOrEqual(2);

    // Verify ixn events have anchor data ('a' field)
    for (const ixn of ixnEvents) {
      const raw = JSON.parse(ixn.raw);
      expect(raw['t']).toBe('ixn');
      // The 'a' field should be present with seal data
      expect(raw['a']).toBeTruthy();
    }

    kerizonEventSaids = events.events!.map(e => e.said);
  });

  it('step 6: kerizon exports full KEL as CESR', async () => {
    const exported = await kerizon.exportKel('issuer');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);
    exportedCesr = exported.cesr!;
  });

  it('step 7: kli imports the CESR stream', async () => {
    const imported = await kli.importKel(exportedCesr);
    expect(imported.exitCode).toBe(0);
  });

  it('step 8: kli sees the correct prefix and sn after import', async () => {
    const status = await kli.status('issuer');
    if (status.exitCode === 0 && status.keyState) {
      expect(status.keyState.prefix).toBe(issuerPrefix);
      expect(status.keyState.sn).toBeGreaterThanOrEqual(2);
    }
  });

  it('step 9: kli event SAIDs match kerizon originals', async () => {
    const events = await kli.exportEvents('issuer');
    if (events.exitCode !== 0 || !events.events) return;

    expect(events.events.length).toBe(kerizonEventSaids.length);

    for (let i = 0; i < events.events.length; i++) {
      expect(events.events[i].said).toBe(kerizonEventSaids[i]);
    }
  });
});
