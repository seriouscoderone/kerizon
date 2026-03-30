import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { KerizonAdapter } from '../src/adapter/kerizon-adapter.js';
import { resolve } from 'node:path';
import { execSync, spawn, type ChildProcess } from 'node:child_process';

const CLI_PATH = resolve(import.meta.dirname, '../../kerizon-cli/dist/cli.js');
const KERIZON_CLI_DIR = resolve(import.meta.dirname, '../../kerizon-cli');

let witnessProc: ChildProcess | undefined;

// Synchronous detection at module load time
let witnessAvailable = false;
try {
  const code = execSync('curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/', {
    encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  witnessAvailable = code !== '000';
} catch { witnessAvailable = false; }

afterAll(async () => {
  if (witnessProc) {
    witnessProc.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 1000));
  }
});

describe.skipIf(!witnessAvailable)('kerizon witness conformance', () => {
  let adapter: KerizonAdapter;
  const ks = `kzwit-${Date.now()}`;

  beforeAll(async () => {
    adapter = new KerizonAdapter({ cliPath: CLI_PATH, useNode: true, keystoreName: ks });
    await adapter.init({ name: ks, nopasscode: true });
  });

  it('witness is running on port 5642', async () => {
    const result = execSync('curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/', { encoding: 'utf-8' });
    expect(result.trim()).not.toBe('000');
  });

  it('OOBI endpoint returns CESR', async () => {
    const result = execSync('curl -s -m2 http://127.0.0.1:5642/oobi/test/witness', { encoding: 'utf-8', timeout: 5000 });
    expect(result).toContain('KERI');
  });

  // Note: Full incept-with-witness requires kerizon CLI to support --receipt-endpoint
  // which POSTs the inception event to the witness HTTP endpoint.
  // For now, test that the witness is reachable and serves valid CESR.

  it('witness serves valid CESR at OOBI endpoint', async () => {
    const result = execSync('curl -s -m2 http://127.0.0.1:5642/oobi/test/witness', { encoding: 'utf-8', timeout: 5000 });
    // Should contain a JSON body with version string
    expect(result).toMatch(/KERI\d{2}JSON/);
  });
});
