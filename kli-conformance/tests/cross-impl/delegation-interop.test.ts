/**
 * Cross-implementation delegation test: kli delegator + kerizon delegate.
 *
 * Exercises delegation as communication between two CLIs -- no witnesses needed:
 *
 * 1. kli creates a transferable delegator identifier
 * 2. kli exports the delegator KEL -> kerizon imports it (so kerizon knows the delegator)
 * 3. kerizon creates a delegated inception with --delpre <delegator-prefix> -> produces a dip event
 * 4. kerizon exports the dip event -> verify it has t:'dip' and di matching delegator
 * 5. kli creates an ixn with a delegation seal {i: delegate-prefix, s: "0", d: delegate-said}
 * 6. Verify kli's KEL contains the seal matching the delegatee's event
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `deleg-kli-${Date.now()}`;
const KS_KERIZON = `deleg-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state across test steps
let delegatorPrefix: string;
let delegatePrefix: string;
let delegateSaid: string;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  kli = new KliAdapter({ keystoreName: KS_KLI, timeout: 30_000 });
  kerizon = new KerizonAdapter({
    keystoreName: KS_KERIZON,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 30_000,
  });

  // Init both keystores
  await kli.init({ name: KS_KLI, nopasscode: true });
  await kerizon.init({ name: KS_KERIZON });
});

describe.skipIf(!KLI_AVAILABLE)('cross-impl delegation: kli delegator + kerizon delegate', () => {
  it('step 1: kli creates a transferable delegator', async () => {
    const result = await kli.incept({
      alias: 'delegator',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    delegatorPrefix = result.prefix!;
  });

  it('step 2: kli exports delegator KEL as CESR', async () => {
    const exported = await kli.exportKel('delegator');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);
  });

  it('step 3: kerizon creates a delegated inception (dip) with --delpre', async () => {
    const result = await kerizon.incept({
      alias: 'delegate',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      delegator: delegatorPrefix,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    delegatePrefix = result.prefix!;
  });

  it('step 4: kerizon dip event has t:"dip" and di matching delegator', async () => {
    const result = await kerizon.exportEvents('delegate');
    expect(result.exitCode).toBe(0);
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBeGreaterThanOrEqual(1);

    const dipEvent = result.events![0];
    expect(dipEvent.type).toBe('dip');
    expect(dipEvent.prefix).toBe(delegatePrefix);

    // Also verify the raw JSON has 'di' field matching the delegator
    const raw = JSON.parse(dipEvent.raw);
    expect(raw['di']).toBe(delegatorPrefix);
    expect(raw['t']).toBe('dip');

    // Capture the SAID for the seal
    delegateSaid = dipEvent.said;
    expect(delegateSaid).toBeTruthy();
  });

  it('step 5: kli creates an ixn anchoring the delegation seal', async () => {
    const seal = {
      i: delegatePrefix,
      s: '0',
      d: delegateSaid,
    };

    const result = await kli.interact({
      alias: 'delegator',
      data: [seal],
    });

    expect(result.exitCode).toBe(0);
  });

  it('step 6: kli KEL contains the seal matching the delegatee event', async () => {
    const result = await kli.exportEvents('delegator');
    expect(result.exitCode).toBe(0);
    expect(result.events).toBeTruthy();

    // The delegator KEL should have at least 2 events: icp + ixn
    expect(result.events!.length).toBeGreaterThanOrEqual(2);

    const ixnEvent = result.events!.find(e => e.type === 'ixn');
    expect(ixnEvent).toBeTruthy();

    const ixnRaw = JSON.parse(ixnEvent!.raw);
    expect(ixnRaw['t']).toBe('ixn');

    // The anchor data ('a' field) should contain the delegation seal
    const anchors = ixnRaw['a'] as Array<Record<string, string>>;
    expect(anchors).toBeTruthy();
    expect(anchors.length).toBeGreaterThanOrEqual(1);

    const matchingSeal = anchors.find(
      (a) => a['i'] === delegatePrefix && a['d'] === delegateSaid,
    );
    expect(matchingSeal).toBeTruthy();
    expect(matchingSeal!['s']).toBe('0');
  });
});
