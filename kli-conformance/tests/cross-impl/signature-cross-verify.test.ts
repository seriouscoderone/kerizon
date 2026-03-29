/**
 * Cross-implementation signature verification.
 *
 * For one CLI to verify another's signatures it must know the signer's
 * public keys, which means it needs the signer's KEL.  The flow is:
 *
 *   signer incepts -> signer exports KEL -> verifier imports KEL -> verifier verifies
 *
 * Directions tested:
 *   A. kerizon signs -> kli verifies  (KEL export kerizon -> import kli)
 *   B. kli signs -> kerizon verifies  (KEL export kli -> import kerizon)
 *      NOTE: direction B is blocked because kerizon importKel is not implemented.
 *
 * Tamper tests flip the text after signing to confirm rejection.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

const KS_KLI = `sig-xver-kli-${Date.now()}`;
const KS_KERIZON = `sig-xver-kzn-${Date.now()}`;

let kli: KliAdapter;
let kerizon: KerizonAdapter;

// Shared state
let kerizonPrefix: string;
let kliPrefix: string;
let kerizonSigs: string[];
let kliSigs: string[];

const SIGN_TEXT = 'hello';
const TAMPERED_TEXT = 'tampered';

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

describe.skipIf(!KLI_AVAILABLE)('cross-impl signature verification', () => {
  // ── Direction A: kerizon signs, kli verifies ──

  describe('direction A: kerizon signs -> kli verifies', () => {
    it('step A1: kerizon incepts a signer identity', async () => {
      const result = await kerizon.incept({
        alias: 'kzn-signer',
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
      });

      expect(result.exitCode).toBe(0);
      expect(result.prefix).toBeTruthy();
      kerizonPrefix = result.prefix!;
    });

    it('step A2: kerizon signs "hello"', async () => {
      const result = await kerizon.sign('kzn-signer', SIGN_TEXT);
      expect(result.exitCode).toBe(0);
      expect(result.signatures).toBeTruthy();
      expect(result.signatures!.length).toBeGreaterThan(0);
      kerizonSigs = result.signatures!;
    });

    it('step A3: kerizon exports KEL -> kli imports it', async () => {
      const exported = await kerizon.exportKel('kzn-signer');
      expect(exported.exitCode).toBe(0);
      expect(exported.cesr).toBeTruthy();

      const imported = await kli.importKel(exported.cesr!);
      expect(imported.exitCode).toBe(0);
    });

    it('step A4: kli verifies kerizon signature -> valid=true', async () => {
      const result = await kli.verify(kerizonPrefix, SIGN_TEXT, kerizonSigs);
      expect(result.exitCode).toBe(0);
      expect(result.valid).toBe(true);
    });

    it('step A5: kli rejects tampered text -> valid=false', async () => {
      const result = await kli.verify(kerizonPrefix, TAMPERED_TEXT, kerizonSigs);
      // Either valid=false or non-zero exit code means rejection
      expect(result.valid === false || result.exitCode !== 0).toBe(true);
    });
  });

  // ── Direction B: kli signs, kerizon verifies ──
  // Blocked because kerizon importKel is not yet implemented.

  describe('direction B: kli signs -> kerizon verifies', () => {
    it('step B1: kli incepts a signer identity', async () => {
      const result = await kli.incept({
        alias: 'kli-signer',
        transferable: true,
        signingKeyCount: 1,
        nextKeyCount: 1,
      });

      expect(result.exitCode).toBe(0);
      expect(result.prefix).toBeTruthy();
      kliPrefix = result.prefix!;
    });

    it('step B2: kli signs "hello"', async () => {
      const result = await kli.sign('kli-signer', SIGN_TEXT);
      expect(result.exitCode).toBe(0);
      expect(result.signatures).toBeTruthy();
      expect(result.signatures!.length).toBeGreaterThan(0);
      kliSigs = result.signatures!;
    });

    it('step B3: kli exports KEL -> kerizon imports', async () => {
      const exported = await kli.exportKel('kli-signer');
      expect(exported.exitCode).toBe(0);
      expect(exported.cesr).toBeTruthy();

      const imported = await kerizon.importKel(exported.cesr!);
      expect(imported.exitCode).toBe(0);
    });

    it('step B4: kerizon verifies kli signature -> valid=true', async () => {
      const result = await kerizon.verify(kliPrefix, SIGN_TEXT, kliSigs);
      expect(result.exitCode).toBe(0);
      expect(result.valid).toBe(true);
    });

    it('step B5: kerizon rejects tampered text -> valid=false', async () => {
      const result = await kerizon.verify(kliPrefix, TAMPERED_TEXT, kliSigs);
      // Either valid=false or non-zero exit code means rejection
      expect(result.valid === false || result.exitCode !== 0).toBe(true);
    });
  });
});
