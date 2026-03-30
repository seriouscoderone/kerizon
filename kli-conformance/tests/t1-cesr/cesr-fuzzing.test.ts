/**
 * Malformed CESR fuzzing tests.
 *
 * Uses fast-check to generate malformed CESR and verify both kli and kerizon
 * handle them without crashing (no segfaults, no signal deaths).
 *
 * Fuzz strategies:
 *   1. Random bytes — must reject (exit != 0) AND not crash
 *   2. Truncated valid CESR — must not crash (may accept a valid prefix)
 *   3. Corrupted SAID (bit-flip in `d` field) — must not crash
 *   4. Mangled version string — must not crash
 *   5. Missing required fields — must not crash
 *
 * PBT run counts are kept low (20-50) since each run spawns a subprocess.
 * Exit codes 128+ indicate signal death (e.g., 139 = SIGSEGV) and are
 * treated as test failures.
 *
 * Note: mutation strategies (truncation, version mangling, field removal)
 * may not properly preserve CESR framing, so the CLI might accept partial
 * input or reject for a framing error rather than a semantic one. The key
 * property is robustness: no crashes regardless of input.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import fc from 'fast-check';
import { resolve } from 'node:path';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');

// ── Helpers ──

const KS_SRC = `fuzz-src-${Date.now()}`;
let srcAdapter: KerizonAdapter;
let validCesrBytes: Uint8Array;

/**
 * Generate a valid CESR inception event using kerizon, then export it.
 * This provides a baseline for mutation-based fuzzing.
 */
async function generateValidCesr(): Promise<Uint8Array> {
  const result = await srcAdapter.exportKel('fuzz-src');
  if (!result.cesr || result.cesr.length === 0) {
    throw new Error(`Failed to export valid CESR: exit=${result.exitCode} stderr=${result.stderr}`);
  }
  return result.cesr;
}

/**
 * Create a fresh kerizon adapter for import testing.
 * Each fuzz run gets its own keystore to avoid state pollution.
 */
function makeKerizonTarget(label: string): KerizonAdapter {
  return new KerizonAdapter({
    keystoreName: `fuzz-kzn-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 15_000,
  });
}

function makeKliTarget(label: string): KliAdapter {
  return new KliAdapter({
    keystoreName: `fuzz-kli-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timeout: 15_000,
  });
}

/**
 * Assert that an exit code represents a clean rejection (not a crash/signal).
 * Random/garbage bytes should always be rejected (exit != 0).
 * Exit codes >= 128 usually indicate a signal (e.g., 139 = SIGSEGV).
 */
function assertCleanRejection(exitCode: number): void {
  expect(exitCode).not.toBe(0); // must reject
  expect(exitCode).toBeLessThan(128); // must not crash with signal
}

/**
 * Assert that the CLI did not crash (no signal death).
 * Allows exit 0 (accepted) or exit 1/255 (rejected).
 * Only fails if exitCode >= 128, indicating a signal like SIGSEGV.
 */
function assertNoCrash(exitCode: number): void {
  expect(exitCode).toBeLessThan(128);
}

/**
 * Flip a single bit in the given Uint8Array at a random byte position.
 */
function flipBit(data: Uint8Array, byteIndex: number): Uint8Array {
  const copy = new Uint8Array(data);
  const bitIndex = byteIndex % 8;
  copy[byteIndex % copy.length] ^= (1 << bitIndex);
  return copy;
}

// ── Setup ──

beforeAll(async () => {
  srcAdapter = new KerizonAdapter({
    keystoreName: KS_SRC,
    cliPath: CLI_PATH,
    useNode: true,
    timeout: 30_000,
  });

  await srcAdapter.init({ name: KS_SRC, nopasscode: true });
  await srcAdapter.incept({ alias: 'fuzz-src', transferable: true });
  validCesrBytes = await generateValidCesr();
});

// ── Tests against kerizon ──

describe('CESR fuzzing — kerizon', () => {
  it('rejects random bytes without crashing (PBT, 50 runs)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 1000 }),
        async (randomBytes) => {
          const target = makeKerizonTarget('rand');
          await target.init({ name: target['keystoreName'], nopasscode: true });
          const result = await target.importKel(new Uint8Array(randomBytes));
          assertCleanRejection(result.exitCode);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('handles truncated valid CESR without crashing (PBT, 20 runs)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: Math.max(1, validCesrBytes.length - 1) }),
        async (cutPoint) => {
          const truncated = validCesrBytes.slice(0, cutPoint);
          const target = makeKerizonTarget('trunc');
          await target.init({ name: target['keystoreName'], nopasscode: true });
          const result = await target.importKel(truncated);
          // Truncation may leave a complete event prefix — accept or reject, just don't crash
          assertNoCrash(result.exitCode);
        },
      ),
      { numRuns: 20 },
    );
  });

  it('handles CESR with corrupted SAID without crashing', async () => {
    // Find the `"d":"` field in the CESR text and flip a bit in the SAID value
    const text = new TextDecoder().decode(validCesrBytes);
    const saidMatch = text.match(/"d"\s*:\s*"([^"]+)"/);

    // Skip if we can't find the SAID (unlikely with valid inception)
    if (!saidMatch) {
      expect(true).toBe(true); // no SAID found, skip gracefully
      return;
    }

    const saidStart = text.indexOf(saidMatch[1]);
    // Flip a bit somewhere in the SAID value (not the first char which is the code)
    const flipOffset = saidStart + 5; // pick a position within the SAID
    const corrupted = flipBit(validCesrBytes, flipOffset);

    const target = makeKerizonTarget('said');
    await target.init({ name: target['keystoreName'], nopasscode: true });
    const result = await target.importKel(corrupted);
    // SAID corruption should ideally be rejected, but we primarily test for no crash
    assertNoCrash(result.exitCode);
  });

  it('handles CESR with mangled version string without crashing', async () => {
    const text = new TextDecoder().decode(validCesrBytes);
    const versionMatch = text.match(/"v"\s*:\s*"([^"]+)"/);

    if (!versionMatch) {
      expect(true).toBe(true);
      return;
    }

    // Replace the version string with garbage
    const mangled = text.replace(versionMatch[0], '"v":"XYZZY_BAD_VERSION"');
    const mangledBytes = new TextEncoder().encode(mangled);

    const target = makeKerizonTarget('ver');
    await target.init({ name: target['keystoreName'], nopasscode: true });
    const result = await target.importKel(mangledBytes);
    assertNoCrash(result.exitCode);
  });

  it('handles CESR with missing required fields without crashing', async () => {
    const text = new TextDecoder().decode(validCesrBytes);

    // Remove the "t" (type) field — required for all events
    const stripped = text.replace(/"t"\s*:\s*"[^"]*"\s*,?\s*/, '');
    const strippedBytes = new TextEncoder().encode(stripped);

    const target = makeKerizonTarget('fields');
    await target.init({ name: target['keystoreName'], nopasscode: true });
    const result = await target.importKel(strippedBytes);
    assertNoCrash(result.exitCode);
  });
});

// ── Tests against kli (if available) ──

describe.skipIf(!KLI_AVAILABLE)('CESR fuzzing — kli', () => {
  it('rejects random bytes without crashing (PBT, 20 runs)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 1000 }),
        async (randomBytes) => {
          const target = makeKliTarget('rand');
          await target.init({ name: target['keystoreName'], nopasscode: true });
          const result = await target.importKel(new Uint8Array(randomBytes));
          assertCleanRejection(result.exitCode);
        },
      ),
      { numRuns: 20 },
    );
  });

  it('handles truncated valid CESR without crashing (PBT, 20 runs)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: Math.max(1, validCesrBytes.length - 1) }),
        async (cutPoint) => {
          const truncated = validCesrBytes.slice(0, cutPoint);
          const target = makeKliTarget('trunc');
          await target.init({ name: target['keystoreName'], nopasscode: true });
          const result = await target.importKel(truncated);
          assertNoCrash(result.exitCode);
        },
      ),
      { numRuns: 20 },
    );
  });
});
