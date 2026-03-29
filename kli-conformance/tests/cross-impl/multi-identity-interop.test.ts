/**
 * Cross-implementation multi-identity test: kerizon -> kli.
 *
 * Verifies that multiple identifiers in the same keystore are correctly
 * isolated and cross-verified:
 *
 *   1. kerizon incepts alice and bob (different keys)
 *   2. kerizon signs "hello" with alice, signs "hello" with bob
 *   3. kerizon exports both KELs -> kli imports both
 *   4. kli verifies alice's signature with alice's prefix -> valid
 *   5. kli verifies bob's signature with bob's prefix -> valid
 *   6. kli verifies alice's signature with bob's prefix -> INVALID
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `multi-id-interop-kli-${Date.now()}`;
const KS_KERIZON = `multi-id-interop-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state
let alicePrefix: string;
let bobPrefix: string;
let aliceSigs: string[];
let bobSigs: string[];

const SIGN_TEXT = 'hello';

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

describe.skipIf(!KLI_AVAILABLE)('cross-impl multi-identity: kerizon -> kli', () => {
  it('step 1: kerizon incepts alice', async () => {
    const result = await kerizon.incept({
      alias: 'alice',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    alicePrefix = result.prefix!;
  });

  it('step 2: kerizon incepts bob', async () => {
    const result = await kerizon.incept({
      alias: 'bob',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });

    expect(result.exitCode).toBe(0);
    expect(result.prefix).toBeTruthy();
    bobPrefix = result.prefix!;
  });

  it('step 3: alice and bob have different prefixes', () => {
    expect(alicePrefix).not.toBe(bobPrefix);
  });

  it('step 4: kerizon signs "hello" with alice', async () => {
    const result = await kerizon.sign('alice', SIGN_TEXT);
    expect(result.exitCode).toBe(0);
    expect(result.signatures).toBeTruthy();
    expect(result.signatures!.length).toBeGreaterThan(0);
    aliceSigs = result.signatures!;
  });

  it('step 5: kerizon signs "hello" with bob', async () => {
    const result = await kerizon.sign('bob', SIGN_TEXT);
    expect(result.exitCode).toBe(0);
    expect(result.signatures).toBeTruthy();
    expect(result.signatures!.length).toBeGreaterThan(0);
    bobSigs = result.signatures!;
  });

  it('step 6: alice and bob produce different signatures', () => {
    // Same text but different keys -> different signatures
    expect(aliceSigs[0]).not.toBe(bobSigs[0]);
  });

  it('step 7: kerizon exports both KELs -> kli imports both', async () => {
    const aliceExport = await kerizon.exportKel('alice');
    expect(aliceExport.exitCode).toBe(0);
    expect(aliceExport.cesr).toBeTruthy();

    const bobExport = await kerizon.exportKel('bob');
    expect(bobExport.exitCode).toBe(0);
    expect(bobExport.cesr).toBeTruthy();

    const aliceImport = await kli.importKel(aliceExport.cesr!);
    expect(aliceImport.exitCode).toBe(0);

    const bobImport = await kli.importKel(bobExport.cesr!);
    expect(bobImport.exitCode).toBe(0);
  });

  it('step 8: kli verifies alice signature with alice prefix -> valid', async () => {
    const result = await kli.verify(alicePrefix, SIGN_TEXT, aliceSigs);
    expect(result.exitCode).toBe(0);
    expect(result.valid).toBe(true);
  });

  it('step 9: kli verifies bob signature with bob prefix -> valid', async () => {
    const result = await kli.verify(bobPrefix, SIGN_TEXT, bobSigs);
    expect(result.exitCode).toBe(0);
    expect(result.valid).toBe(true);
  });

  it('step 10: kli verifies alice signature with bob prefix -> INVALID', async () => {
    const result = await kli.verify(bobPrefix, SIGN_TEXT, aliceSigs);
    // Wrong keys -> either valid=false or non-zero exit code
    expect(result.valid === false || result.exitCode !== 0).toBe(true);
  });
});
