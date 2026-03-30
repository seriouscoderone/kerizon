/**
 * Challenge-response tests against kerizon CLI.
 *
 * kerizon-cli does not yet implement `challenge generate` / `challenge respond`
 * / `challenge verify`. These tests document the gap and verify the adapter
 * returns clean "not implemented" results rather than crashing.
 *
 * When kerizon-cli gains challenge support, remove the skip and mirror
 * the kli challenge-response.test.ts structure.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { KerizonAdapter } from '../src/adapter/kerizon-adapter.js';

const CLI_PATH = resolve(import.meta.dirname, '../../kerizon-cli/dist/cli.js');
const KERIZON_AVAILABLE = existsSync(CLI_PATH);

let adapter: KerizonAdapter;

beforeAll(async () => {
  if (!KERIZON_AVAILABLE) return;
  const ks = `kz-chal-${Date.now()}`;
  adapter = new KerizonAdapter({ cliPath: CLI_PATH, useNode: true, keystoreName: ks });
  await adapter.init({ name: ks, nopasscode: true });
});

describe.skipIf(!KERIZON_AVAILABLE)('kerizon challenge-response - adapter coverage', () => {
  it('challengeGenerate returns clean not-implemented result', async () => {
    const result = await adapter.challengeGenerate(128);
    // kerizon-cli does not implement challenge yet
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Not implemented');
    expect(result.words).toBeUndefined();
  });

  it('challengeRespond returns clean not-implemented result', async () => {
    const result = await adapter.challengeRespond({
      alias: 'test',
      recipient: 'EFAKE',
      words: 'apple banana cherry',
    });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Not implemented');
  });

  it('challengeVerify returns clean not-implemented result', async () => {
    const result = await adapter.challengeVerify({
      alias: 'test',
      signer: 'EFAKE',
      words: 'apple banana cherry',
    });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Not implemented');
    expect(result.verified).toBeUndefined();
  });
});

describe('kerizon challenge-response - pending implementation', () => {
  it.todo('challenge generate produces word list (blocked: kerizon-cli needs challenge command)');
  it.todo('challenge respond + verify flow (blocked: kerizon-cli needs challenge command + witnesses)');
});
