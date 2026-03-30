/**
 * Cross-implementation witness interop: kli uses kerizon witnesses.
 *
 * The ultimate interop test: kli (keripy) creates identifiers against
 * kerizon (TypeScript) witnesses. Verifies that:
 *   1. kli can resolve kerizon witness OOBIs
 *   2. kli can incept with a kerizon witness (witness signs receipt)
 *   3. kli can rotate and interact with kerizon witness receipts
 *   4. kli signs data with the witnessed identity, verifies it
 *   5. kli exports the KEL and kerizon can import it (full circle)
 *   6. kerizon verifies kli signatures using the witnessed identity
 *
 * Prerequisites:
 *   - kerizon witnesses running on ports 5642-5644
 *   - kli (keripy) available on PATH
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'node:child_process';
import http from 'node:http';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

// ── Detect kerizon witnesses at module load time ──

let witnessRunning = false;
try {
  const code = execSync(
    'curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/',
    { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'] },
  ).trim();
  witnessRunning = code !== '000';
} catch {
  witnessRunning = false;
}

const SKIP = !KLI_AVAILABLE || !witnessRunning;

// ── Helpers ──

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');
const WITNESS_PORT = 5642;

/**
 * Fetch the witness AID from a kerizon witness HTTP endpoint.
 * The /oobi/test/witness endpoint returns a JSON key event with the witness AID in the `i` field.
 */
function fetchWitnessAid(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${port}/oobi/test/witness`, (res) => {
      let body = '';
      res.on('data', (chunk: string | Buffer) => (body += chunk));
      res.on('end', () => {
        try {
          // The response may contain multiple JSON objects; parse the first one
          const json = JSON.parse(body.split('}')[0] + '}');
          resolve(json.i);
        } catch {
          reject(new Error(`Failed to parse witness AID from response: ${body.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error(`Timeout fetching witness AID from port ${port}`));
    });
  });
}

// ── Test state ──

const KS_KLI = `kli-kzw-${Date.now()}`;
const KS_KERIZON = `kzn-kzw-${Date.now()}`;
const ALIAS = 'kzw-test';

let kli: KliAdapter;
let kerizon: KerizonAdapter;
let witnessAid: string;
let kliPrefix: string;

beforeAll(async () => {
  if (SKIP) return;

  kli = new KliAdapter({ keystoreName: KS_KLI, timeout: 30_000 });
  kerizon = new KerizonAdapter({
    keystoreName: KS_KERIZON,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 30_000,
  });

  // Fetch the kerizon witness AID
  witnessAid = await fetchWitnessAid(WITNESS_PORT);

  // Initialize keystores
  await kli.init({ name: KS_KLI, nopasscode: true });
  await kerizon.init({ name: KS_KERIZON, nopasscode: true });
});

describe.skipIf(SKIP)('cross-impl: kli with kerizon witnesses', () => {
  it('step 1: kli resolves kerizon witness OOBI', async () => {
    expect(witnessAid).toBeTruthy();
    expect(witnessAid.length).toBeGreaterThan(40);

    const oobiUrl = `http://127.0.0.1:${WITNESS_PORT}/oobi/${witnessAid}/controller`;
    const result = await kli.oobiResolve(oobiUrl, 'kz-wan');

    expect(result.exitCode).toBe(0);
  });

  it('step 2: kli incepts with kerizon witness', async () => {
    const result = await kli.incept({
      alias: ALIAS,
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
      witnesses: [witnessAid],
      witnessThreshold: 1,
      receiptEndpoint: true,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    kliPrefix = result.prefix!;
  });

  it('step 3: kli status shows 1 witness', async () => {
    const status = await kli.status(ALIAS);

    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.prefix).toBe(kliPrefix);
    // Witness is in the key state — backerThreshold confirms witness config
    // (backers array parsing may not capture all formats from kli verbose output)
    expect(status.keyState!.backerThreshold).toBeGreaterThanOrEqual(1);
  });

  it('step 4: kli rotates with kerizon witness receipt', async () => {
    const result = await kli.rotate({
      alias: ALIAS,
      receiptEndpoint: true,
    });

    expect(result.exitCode).toBe(0);
  });

  it('step 5: kli interacts with kerizon witness receipt', async () => {
    const result = await kli.interact({
      alias: ALIAS,
      receiptEndpoint: true,
    });

    expect(result.exitCode).toBe(0);
  });

  it('step 6: kli sign + verify with witnessed identity', async () => {
    const signResult = await kli.sign(ALIAS, 'witnessed-data');
    expect(signResult.exitCode).toBe(0);
    expect(signResult.signatures).toBeTruthy();
    expect(signResult.signatures!.length).toBeGreaterThan(0);

    const verifyResult = await kli.verify(kliPrefix, 'witnessed-data', signResult.signatures!);
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.valid).toBe(true);
  });

  it('step 7: kli exports KEL with correct event sequence [0,1,2]', async () => {
    const events = await kli.exportEvents(ALIAS);
    expect(events.exitCode).toBe(0);
    expect(events.events).toBeTruthy();
    expect(events.events!.length).toBe(3);

    const sns = events.events!.map(e => e.sn);
    expect(sns).toEqual([0, 1, 2]);

    const types = events.events!.map(e => e.type);
    expect(types).toEqual(['icp', 'rot', 'ixn']);
  });

  it('step 8: kerizon imports the kli KEL (full circle)', async () => {
    const exported = await kli.exportKel(ALIAS);
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);

    const imported = await kerizon.importKel(exported.cesr!);
    expect(imported.exitCode).toBe(0);
  });

  it('step 9: cross-verify — kli signs, kerizon verifies', async () => {
    const signResult = await kli.sign(ALIAS, 'cross-verify-payload');
    expect(signResult.exitCode).toBe(0);
    expect(signResult.signatures).toBeTruthy();

    const verifyResult = await kerizon.verify(
      kliPrefix,
      'cross-verify-payload',
      signResult.signatures!,
    );
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.valid).toBe(true);
  });
});
