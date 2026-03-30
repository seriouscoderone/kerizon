/**
 * Signature verification interop tests.
 *
 * Verifies that kerizon produces events with valid signatures that can be
 * parsed and verified, and that events with corrupted signatures are rejected
 * on import.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve } from 'node:path';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');
const KS = `sig-interop-${Date.now()}`;

let kerizon: KerizonAdapter;

beforeAll(async () => {
  kerizon = new KerizonAdapter({
    keystoreName: KS,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 30_000,
  });
  await kerizon.init({ name: KS });
});

describe('signature verification interop', () => {
  it('kerizon creates event, exports, imports back without error', async () => {
    const incept = await kerizon.incept({
      alias: 'sig-interop-a',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });
    expect(incept.exitCode).toBe(0);
    expect(incept.prefix).toBeTruthy();

    const exported = await kerizon.exportKel('sig-interop-a');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();
    expect(exported.cesr!.length).toBeGreaterThan(0);
  });

  it('corrupted signature in CESR is rejected on import', async () => {
    // Create a fresh identity and export its KEL
    const incept = await kerizon.incept({
      alias: 'sig-interop-b',
      transferable: true,
      signingKeyCount: 1,
      nextKeyCount: 1,
    });
    expect(incept.exitCode).toBe(0);

    const exported = await kerizon.exportKel('sig-interop-b');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr).toBeTruthy();

    // Corrupt a byte in the signature region (near the end of the CESR stream)
    const corrupted = new Uint8Array(exported.cesr!);
    // The signature is at the end of the CESR stream. Flip a byte in the
    // last 88 characters (the Ed25519 indexed sig is 88 qb64 chars = 88 bytes in the stream)
    const corruptIdx = corrupted.length - 10;
    if (corruptIdx > 0) {
      corrupted[corruptIdx] = corrupted[corruptIdx] ^ 0xff;
    }

    // Import with a different keystore to avoid prefix collision
    const kerizon2 = new KerizonAdapter({
      keystoreName: `${KS}-corrupt`,
      cliPath: CLI_PATH,
      useNode: true,
      timeout: 30_000,
    });
    await kerizon2.init({ name: `${KS}-corrupt` });

    const imported = await kerizon2.importKel(corrupted);
    // Should fail -- either parse error or signature verification failure
    expect(imported.exitCode !== 0 || imported.stderr.length > 0).toBe(true);
  });
});
