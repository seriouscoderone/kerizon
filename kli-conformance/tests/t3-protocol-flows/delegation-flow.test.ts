/**
 * Delegation flow: delegator creates identifier → delegatee creates
 * delegated identifier → delegator confirms → verify seal linkage.
 *
 * Requires kli + witness demo running.
 * This is a complex multi-party test.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { KliAdapter, DEMO_WITNESSES } from '../../src/adapter/kli-adapter.js';
import type { WitnessHandle } from '../../src/adapter/types.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let delegatorAdapter: KliAdapter;
let delegateAdapter: KliAdapter;
let witnesses: WitnessHandle | undefined;

const KS_DELEGATOR = `delegator-test-${Date.now()}`;
const KS_DELEGATE = `delegate-test-${Date.now()}`;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;

  delegatorAdapter = new KliAdapter({
    keystoreName: KS_DELEGATOR,
    timeout: 60_000,
  });
  delegateAdapter = new KliAdapter({
    keystoreName: KS_DELEGATE,
    timeout: 60_000,
  });

  // Init both keystores
  await delegatorAdapter.init({ name: KS_DELEGATOR, nopasscode: true });
  await delegateAdapter.init({ name: KS_DELEGATE, nopasscode: true });
});

afterAll(async () => {
  if (witnesses) await witnesses.stop();
});

describe.skipIf(!KLI_AVAILABLE)('delegation flow', () => {
  it('delegation invariants hold for non-delegated identifiers', async () => {
    // Simpler test: verify non-delegated identifiers have no di field
    await delegatorAdapter.incept({ alias: 'non-del', transferable: true });

    const result = await delegatorAdapter.exportEvents('non-del');
    expect(result.events).toBeTruthy();

    const icp = JSON.parse(result.events![0].raw);
    expect(icp['t']).toBe('icp'); // not 'dip'
    // Non-delegated inception should not have 'di' field
    expect(icp['di']).toBeUndefined();
  });

  // Full delegation requires witnesses with endpoint records for OOBI exchange.
  // See delegation-extended.test.ts for the full version (skips when witnesses unavailable).
  it.todo('delegated inception creates correct bidirectional peg (blocked: requires witnesses + OOBI exchange)');
  it.todo('delegated rotation is confirmed by delegator (blocked: requires witnesses + OOBI exchange)');
});
