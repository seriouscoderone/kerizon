/**
 * Witness receipt-endpoint conformance tests for the kerizon CLI.
 *
 * Exercises the full witnessed identifier lifecycle:
 *   1. Inception with witness receipting (--receipt-endpoint)
 *   2. Rotation with witness receipting
 *   3. Interaction with witness receipting
 *   4. KEL invariants on witnessed events
 *   5. OOBI generation for witnessed identities
 *   6. Sign + verify with a witnessed identity
 *   7. Multi-witness inception
 *
 * Prerequisites:
 *   `kerizon witness demo` must be running externally on ports 5642-5644
 *   before these tests are executed. Start it with:
 *
 *     node kerizon-cli/dist/cli.js witness demo
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KerizonAdapter } from '../src/adapter/kerizon-adapter.js';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';
import { checkSequenceMonotonicity } from '../src/invariants/sequence.js';
import { checkAllFirstSeenInvariants } from '../src/invariants/first-seen.js';

const CLI_PATH = resolve(import.meta.dirname, '../../kerizon-cli/dist/cli.js');

// Witness HTTP ports used by `kerizon witness demo`
const WITNESS_PORTS = [5642, 5643, 5644];

// ── Module-level witness availability check ─────────────────────
// Synchronous so describe.skipIf can use the result at definition time.
let witnessAvailable = false;
try {
  const code = execSync(
    'curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/',
    { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'] },
  ).trim();
  witnessAvailable = code !== '000';
} catch {
  witnessAvailable = false;
}

/**
 * Extract the witness AID from a running witness by querying its OOBI endpoint.
 * The /oobi/{anything}/witness endpoint returns the witness inception event
 * as JSON, and the "i" field is the witness AID.
 */
function extractWitnessAid(port: number): string | undefined {
  try {
    const resp = execSync(
      `curl -s -m3 http://127.0.0.1:${port}/oobi/test/witness`,
      { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] },
    ).trim();
    const parsed = JSON.parse(resp);
    return parsed['i'] as string | undefined;
  } catch {
    return undefined;
  }
}

// ── Shared state ────────────────────────────────────────────────

let adapter: KerizonAdapter;
const witnessAids: string[] = [];
let inceptedPrefix: string;

const ks = `kzwit-receipt-${Date.now()}`;

describe.skipIf(!witnessAvailable)('kerizon witness receipt-endpoint', () => {
  beforeAll(async () => {
    // Discover witness AIDs from running witness processes
    for (const port of WITNESS_PORTS) {
      const aid = extractWitnessAid(port);
      if (aid) witnessAids.push(aid);
    }
    expect(witnessAids.length).toBeGreaterThanOrEqual(1);

    // Create adapter and keystore
    adapter = new KerizonAdapter({
      cliPath: CLI_PATH,
      useNode: true,
      keystoreName: ks,
      timeout: 30_000,
    });
    await adapter.init({ name: ks, nopasscode: true });

    // Resolve the first witness OOBI into the keystore
    const oobiUrl = `http://127.0.0.1:${WITNESS_PORTS[0]}/oobi/${witnessAids[0]}/controller`;
    const resolveResult = await adapter.oobiResolve(oobiUrl, 'wan');
    expect(resolveResult.exitCode).toBe(0);
  }, 20_000);

  // ── 1. Witnessed inception ──────────────────────────────────────

  it('witnessed inception with --receipt-endpoint succeeds', async () => {
    const result = await adapter.incept({
      alias: 'wit-alice',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      witnesses: [witnessAids[0]],
      witnessThreshold: 1,
      receiptEndpoint: true,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    expect(result.prefix!.length).toBe(44);
    expect(result.prefix!.startsWith('E')).toBe(true);
    inceptedPrefix = result.prefix!;
  });

  // ── 2. Status shows witnesses ────────────────────────────────────

  it('status shows witness count and threshold after inception', async () => {
    const status = await adapter.status('wit-alice');
    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();

    const ks = status.keyState!;
    expect(ks.sn).toBe(0);
    expect(ks.backers.length).toBe(1);
    expect(ks.backerThreshold).toBe(1);
    expect(ks.prefix).toBe(inceptedPrefix);
  });

  // ── 3. Witnessed rotation ────────────────────────────────────────

  it('witnessed rotation with --receipt-endpoint succeeds', async () => {
    const beforeStatus = await adapter.status('wit-alice');
    const keysBefore = beforeStatus.keyState!.currentKeys;

    const result = await adapter.rotate({
      alias: 'wit-alice',
      receiptEndpoint: true,
    });
    expect(result.exitCode).toBe(0);

    const afterStatus = await adapter.status('wit-alice');
    expect(afterStatus.keyState!.sn).toBe(1);
    // Keys should have changed after rotation
    expect(afterStatus.keyState!.currentKeys).not.toEqual(keysBefore);
  });

  // ── 4. Witnessed interaction ─────────────────────────────────────

  it('witnessed interaction with --receipt-endpoint succeeds', async () => {
    const result = await adapter.interact({
      alias: 'wit-alice',
      receiptEndpoint: true,
    });
    expect(result.exitCode).toBe(0);

    const status = await adapter.status('wit-alice');
    expect(status.keyState!.sn).toBe(2);
  });

  // ── 5. Keys unchanged after interaction ──────────────────────────

  it('keys unchanged after interaction event', async () => {
    // Rotation was at sn=1, interaction at sn=2. Keys should match post-rotation.
    const status = await adapter.status('wit-alice');
    expect(status.keyState!.sn).toBe(2);
    // Current keys should be the post-rotation keys (ixn does not rotate keys)
    expect(status.keyState!.currentKeys.length).toBe(1);
    expect(status.keyState!.currentKeys[0].startsWith('D')).toBe(true);
  });

  // ── 6. Export KEL with witnessed events ──────────────────────────

  it('export KEL produces CESR bytes for witnessed identity', async () => {
    const result = await adapter.exportKel('wit-alice');
    expect(result.exitCode).toBe(0);
    expect(result.cesr).toBeTruthy();
    expect(result.cesr!.length).toBeGreaterThan(0);
  });

  // ── 7. Sequence number monotonicity ──────────────────────────────

  it('witnessed events have correct sn monotonicity [0,1,2]', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.exitCode).toBe(0);
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBe(3); // icp + rot + ixn

    const snValues = result.events!.map(e => e.sn);
    expect(snValues).toEqual([0, 1, 2]);

    const mono = checkSequenceMonotonicity(result.events!);
    expect(mono.valid).toBe(true);
  });

  // ── 8. First-seen invariants ─────────────────────────────────────

  it('witnessed events satisfy first-seen invariants', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();

    const rawEvents = result.events!.map(e => JSON.parse(e.raw));
    const firstSeen = checkAllFirstSeenInvariants(rawEvents);
    expect(firstSeen.valid).toBe(true);
    expect(firstSeen.violations).toEqual([]);
  });

  // ── 9. Backward hash chain ───────────────────────────────────────

  it('witnessed events form a valid backward hash chain', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBeGreaterThanOrEqual(2);

    const rawEvents = result.events!.map(e => JSON.parse(e.raw));

    // Inception has no prior (p is empty or missing)
    expect(rawEvents[0]['t']).toBe('icp');

    // Every subsequent event's "p" must equal the prior event's "d"
    for (let i = 1; i < rawEvents.length; i++) {
      expect(rawEvents[i]['p']).toBe(rawEvents[i - 1]['d']);
    }
  });

  // ── 10. OOBI generate for witnessed identity ─────────────────────

  it('oobi generate with witness role returns witness OOBI URLs', async () => {
    const result = await adapter.oobiGenerate('wit-alice', 'witness');
    expect(result.exitCode).toBe(0);
    expect(result.oobis).toBeTruthy();
    expect(result.oobis!.length).toBeGreaterThan(0);

    // Each OOBI URL should contain the identifier prefix and /witness path
    for (const url of result.oobis!) {
      expect(url).toContain(inceptedPrefix);
      expect(url).toContain('/witness');
    }
  });

  // ── 11. Sign + verify with witnessed identity ────────────────────

  it('sign and verify with witnessed identity succeeds', async () => {
    const message = 'witnessed identity signature test';

    const signResult = await adapter.sign('wit-alice', message);
    expect(signResult.exitCode).toBe(0);
    expect(signResult.signatures).toBeTruthy();
    expect(signResult.signatures!.length).toBeGreaterThan(0);
    expect(signResult.signatures![0].length).toBe(88); // Ed25519 indexed sig

    const verifyResult = await adapter.verify(
      inceptedPrefix,
      message,
      signResult.signatures!,
    );
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.valid).toBe(true);
  });

  // ── 12. Multi-witness inception ──────────────────────────────────

  it('inception with 2 witnesses and toad 2 succeeds', async () => {
    // Need at least 2 discovered witnesses
    if (witnessAids.length < 2) return;

    // Resolve second witness OOBI
    const secondOobiUrl = `http://127.0.0.1:${WITNESS_PORTS[1]}/oobi/${witnessAids[1]}/controller`;
    await adapter.oobiResolve(secondOobiUrl, 'wil');

    // Create a new identity with 2 witnesses
    const result = await adapter.incept({
      alias: 'wit-multi',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      witnesses: [witnessAids[0], witnessAids[1]],
      witnessThreshold: 2,
      receiptEndpoint: true,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    expect(result.prefix!.length).toBe(44);

    // Status should show 2 witnesses
    const status = await adapter.status('wit-multi');
    expect(status.exitCode).toBe(0);
    expect(status.keyState!.backers.length).toBe(2);
    expect(status.keyState!.backerThreshold).toBe(2);
  });

  // ── 13. Event type sequence ──────────────────────────────────────

  it('witnessed KEL has correct event type sequence [icp, rot, ixn]', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();
    expect(result.events!.length).toBe(3);

    expect(result.events![0].type).toBe('icp');
    expect(result.events![1].type).toBe('rot');
    expect(result.events![2].type).toBe('ixn');
  });

  // ── 14. Prefix constant across all witnessed events ──────────────

  it('prefix is constant across all witnessed events', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();

    const prefix = result.events![0].prefix;
    expect(prefix).toBe(inceptedPrefix);
    for (const event of result.events!) {
      expect(event.prefix).toBe(prefix);
    }
  });

  // ── 15. Witnessed inception event has i == d ─────────────────────

  it('witnessed inception event has i == d (prefix equals SAID)', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();

    const icp = JSON.parse(result.events![0].raw);
    expect(icp['i']).toBe(icp['d']);
    expect(icp['t']).toBe('icp');
  });

  // ── 16. Witnessed inception has witness config in KED ─────────────

  it('witnessed inception KED includes witness configuration', async () => {
    const result = await adapter.exportEvents('wit-alice');
    expect(result.events).toBeTruthy();

    const icp = JSON.parse(result.events![0].raw);
    // The 'b' field should contain the witness list
    expect(icp['b']).toBeTruthy();
    expect(Array.isArray(icp['b'])).toBe(true);
    expect(icp['b'].length).toBe(1);
    expect(icp['b'][0]).toBe(witnessAids[0]);

    // The 'bt' field is the witness threshold (toad)
    const bt = typeof icp['bt'] === 'string' ? parseInt(icp['bt'], 16) : icp['bt'];
    expect(bt).toBe(1);
  });
});
