/**
 * Model-based tests for the KEL state machine.
 *
 * Each fast-check property run gets its own fresh keystore to avoid
 * alias collisions between runs.
 *
 * Requires kli to be installed. Skips if not available.
 */

import { describe, it } from 'vitest';
import fc from 'fast-check';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import {
  initialModel,
  arbTransferableCommands,
  arbNonTransferableCommands,
  arbEstOnlyCommands,
} from '../../src/models/kel-state-machine.js';
import { KLI_AVAILABLE } from '../kli-available.js';

let runCounter = 0;

/** Create a fresh adapter with its own keystore for each property run. */
async function freshAdapter(): Promise<KliAdapter> {
  const ksName = `model-${Date.now()}-${runCounter++}`;
  const adapter = new KliAdapter({ keystoreName: ksName });
  await adapter.init({ name: ksName, nopasscode: true });
  return adapter;
}

describe('KEL state machine model tests', () => {
  describe.skipIf(!KLI_AVAILABLE)('transferable identifier lifecycle', () => {
    it('random incept + rotate/interact sequences maintain consistent state', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbTransferableCommands('model-test'),
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

  describe.skipIf(!KLI_AVAILABLE)('non-transferable identifier', () => {
    it('rotation fails for non-transferable identifier', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbNonTransferableCommands('nt-test'),
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

  describe.skipIf(!KLI_AVAILABLE)('establishment-only identifier', () => {
    it('interaction fails for establishment-only identifier', async () => {
      await fc.assert(
        fc.asyncProperty(
          arbEstOnlyCommands('eo-test'),
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
