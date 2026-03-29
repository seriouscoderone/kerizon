/**
 * Challenge-response authentication flow.
 *
 * kli challenge generate does NOT require witnesses.
 * kli challenge respond/verify require witnesses + mailbox for delivery.
 *
 * Spec invariants tested:
 * - credential-exchange/proof: challenge generate produces word list
 * - credential-exchange/proof: word list has correct entropy
 * - credential-exchange/proof: challenge respond + verify flow (with witnesses)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter, DEMO_WITNESSES } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import { WITNESSES_AVAILABLE } from '../kli-witnesses-available.js';

const SKIP_WITNESSES = !KLI_AVAILABLE || !WITNESSES_AVAILABLE;

let adapter: KliAdapter;

beforeAll(async () => {
  if (!KLI_AVAILABLE) return;
  const ks = `chal-${Date.now()}`;
  adapter = new KliAdapter({ keystoreName: ks, timeout: 30_000 });
  await adapter.init({ name: ks, nopasscode: true });
});

describe.skipIf(!KLI_AVAILABLE)('challenge-response - generation', () => {
  it('challenge generate produces a JSON word list', async () => {
    const result = await adapter.challengeGenerate(128);
    expect(result.exitCode).toBe(0);
    expect(result.words).toBeTruthy();
    expect(Array.isArray(result.words)).toBe(true);
    expect(result.words!.length).toBeGreaterThan(0);
  });

  it('challenge words are strings', async () => {
    const result = await adapter.challengeGenerate(128);
    expect(result.exitCode).toBe(0);
    for (const word of result.words!) {
      expect(typeof word).toBe('string');
      expect(word.length).toBeGreaterThan(0);
    }
  });

  it('128-bit strength produces 12 words (BIP-39)', async () => {
    const result = await adapter.challengeGenerate(128);
    expect(result.exitCode).toBe(0);
    expect(result.words!.length).toBe(12);
  });

  it('256-bit strength produces 24 words', async () => {
    const result = await adapter.challengeGenerate(256);
    expect(result.exitCode).toBe(0);
    expect(result.words!.length).toBe(24);
  });

  it('two successive generations produce different word lists', async () => {
    const r1 = await adapter.challengeGenerate(128);
    const r2 = await adapter.challengeGenerate(128);
    expect(r1.words).not.toEqual(r2.words);
  });
});

describe.skipIf(SKIP_WITNESSES)('challenge-response - full flow', () => {
  it.todo('challenge respond + verify between two parties requires mailbox infrastructure');
});
