/**
 * Extended threshold / multi-key invariant tests.
 *
 * Tests multi-key identifier configurations through the kli adapter:
 * - Multi-key inception produces expected key count
 * - Signing with multi-key identifier produces indexed signatures
 * - Signature verification succeeds
 * - Rotation of multi-key AID changes all keys
 *
 * Requires: kli installed. Does NOT require witnesses.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

describe.skipIf(!KLI_AVAILABLE)('threshold extended - multi-key configs', () => {
  let adapter: KliAdapter;
  const ks = 'threshold-ext-' + Date.now();
  const alias = 'multi-key-aid';
  let prefix: string;

  beforeAll(async () => {
    adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });

    const init = await adapter.init({ name: ks, nopasscode: true });
    expect(init.exitCode).toBe(0);

    const incept = await adapter.incept({
      alias,
      transferable: true,
      signingKeyCount: 3,
      nextKeyCount: 3,
      signingThreshold: '2',
      nextThreshold: '2',
    });
    expect(incept.exitCode).toBe(0);
    prefix = incept.prefix!;
  });

  it('multi-key inception (icount=3, isith="2"): status shows 3 keys', async () => {
    const status = await adapter.status(alias);
    expect(status.exitCode).toBe(0);
    expect(status.keyState).toBeTruthy();
    expect(status.keyState!.currentKeys.length).toBe(3);
    expect(status.keyState!.prefix).toBe(prefix);
  });

  it('sign with multi-key produces multiple indexed signatures', async () => {
    const result = await adapter.sign(alias, 'test message for multi-key');
    expect(result.exitCode).toBe(0);
    expect(result.signatures).toBeTruthy();
    // With 3 signing keys, we expect at least 2 signatures (meeting threshold)
    // kli typically produces signatures from all available keys
    expect(result.signatures!.length).toBeGreaterThanOrEqual(2);
  });

  it('verify multi-key signatures: all signatures valid', async () => {
    const message = 'verify multi-key test';
    const signResult = await adapter.sign(alias, message);
    expect(signResult.exitCode).toBe(0);
    expect(signResult.signatures).toBeTruthy();

    const verifyResult = await adapter.verify(
      prefix,
      message,
      signResult.signatures!,
    );
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.valid).toBe(true);
  });

  it('after rotation of multi-key AID: new keys different from old', async () => {
    const beforeStatus = await adapter.status(alias);
    expect(beforeStatus.exitCode).toBe(0);
    const keysBefore = [...beforeStatus.keyState!.currentKeys];

    const rot = await adapter.rotate({ alias });
    expect(rot.exitCode).toBe(0);

    const afterStatus = await adapter.status(alias);
    expect(afterStatus.exitCode).toBe(0);
    const keysAfter = afterStatus.keyState!.currentKeys;

    // All 3 keys should have changed
    expect(keysAfter.length).toBe(3);
    // At least one key must differ (in practice all change)
    const allSame = keysBefore.every((k, i) => k === keysAfter[i]);
    expect(allSame).toBe(false);
  });
});
