/**
 * Model-based tests for the KEL state machine against kerizon CLI.
 *
 * Same model and fast-check commands as kel-state-machine.test.ts,
 * but driven through the KerizonAdapter instead of KliAdapter.
 *
 * Each fast-check property run gets its own fresh keystore to avoid
 * alias collisions between runs.
 *
 * Requires kerizon-cli dist to be built. Skips if cli.js not found.
 */

import { describe, it } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import fc from 'fast-check';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import {
  initialModel,
  arbTransferableCommands,
  arbNonTransferableCommands,
  arbEstOnlyCommands,
} from '../../src/models/kel-state-machine.js';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');
const KERIZON_AVAILABLE = existsSync(CLI_PATH);

let runCounter = 0;

/** Create a fresh kerizon adapter with its own keystore for each property run. */
async function freshAdapter(): Promise<KerizonAdapter> {
  const ks = `model-kz-${Date.now()}-${runCounter++}`;
  const adapter = new KerizonAdapter({ cliPath: CLI_PATH, useNode: true, keystoreName: ks });
  await adapter.init({ name: ks, nopasscode: true });
  return adapter;
}

describe('KEL state machine model tests (kerizon)', () => {
  describe.skipIf(!KERIZON_AVAILABLE)('transferable identifier lifecycle', () => {
    it('random incept + rotate/interact sequences maintain consistent state', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbTransferableCommands('model-kz-test'),
          async (commands) => {
            const adapter = await freshAdapter();
            const model = initialModel();
            for (const cmd of commands) {
              if (cmd.check(model)) {
                await cmd.run(model, adapter);
              }
            }
          },
        ),
        { numRuns: 5 },
      );
    });
  });

  describe.skipIf(!KERIZON_AVAILABLE)('non-transferable identifier', () => {
    it('rotation fails for non-transferable identifier', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbNonTransferableCommands('kz-nt-test'),
          async (commands) => {
            const adapter = await freshAdapter();
            const model = initialModel();
            for (const cmd of commands) {
              if (cmd.check(model)) {
                await cmd.run(model, adapter);
              }
            }
          },
        ),
        { numRuns: 3 },
      );
    });
  });

  describe.skipIf(!KERIZON_AVAILABLE)('establishment-only identifier', () => {
    it('interaction fails for establishment-only identifier', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbEstOnlyCommands('kz-eo-test'),
          async (commands) => {
            const adapter = await freshAdapter();
            const model = initialModel();
            for (const cmd of commands) {
              if (cmd.check(model)) {
                await cmd.run(model, adapter);
              }
            }
          },
        ),
        { numRuns: 3 },
      );
    });
  });
});
