import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { KerizonAdapter } from '../src/adapter/kerizon-adapter.js';
import { resolve } from 'node:path';
import { execSync, spawn, type ChildProcess } from 'node:child_process';

const CLI_PATH = resolve(import.meta.dirname, '../../kerizon-cli/dist/cli.js');
const KERIZON_CLI_DIR = resolve(import.meta.dirname, '../../kerizon-cli');

let witnessProc: ChildProcess | undefined;
let witnessAvailable = false;

beforeAll(async () => {
  // Start kerizon witness demo in background
  try {
    witnessProc = spawn('node', [CLI_PATH, 'witness', 'demo'], {
      cwd: KERIZON_CLI_DIR,
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: false,
    });
    // Wait for witness to be ready
    await new Promise(resolve => setTimeout(resolve, 3000));
    // Check if HTTP port responds
    try {
      execSync('curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/', { timeout: 3000 });
      witnessAvailable = true;
    } catch { witnessAvailable = false; }
  } catch { witnessAvailable = false; }
}, 15000);

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
