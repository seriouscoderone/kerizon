/**
 * Temporary environment management for CLI tests.
 * Creates isolated temp directories for keystores and config files.
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export interface TempEnv {
  /** Base temp directory for this test environment */
  readonly dir: string;

  /** Write a JSON config file and return its path. */
  writeConfig(name: string, config: Record<string, unknown>): Promise<string>;

  /** Write arbitrary text to a file and return its path. */
  writeFile(name: string, content: string): Promise<string>;

  /** Write binary data to a file and return its path. */
  writeBinary(name: string, data: Uint8Array): Promise<string>;

  /** Clean up the temp directory. */
  cleanup(): Promise<void>;
}

/** Create a new temporary environment. */
export async function createTempEnv(prefix: string = 'kli-conformance-'): Promise<TempEnv> {
  const dir = await mkdtemp(join(tmpdir(), prefix));

  return {
    dir,

    async writeConfig(name: string, config: Record<string, unknown>): Promise<string> {
      const path = join(dir, name);
      await writeFile(path, JSON.stringify(config, null, 2));
      return path;
    },

    async writeFile(name: string, content: string): Promise<string> {
      const path = join(dir, name);
      await writeFile(path, content);
      return path;
    },

    async writeBinary(name: string, data: Uint8Array): Promise<string> {
      const path = join(dir, name);
      await writeFile(path, data);
      return path;
    },

    async cleanup(): Promise<void> {
      await rm(dir, { recursive: true, force: true });
    },
  };
}
