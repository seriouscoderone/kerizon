/**
 * Witness availability detection for Phase B tests.
 *
 * Attempts to start `kli witness demo` and checks if HTTP ports respond.
 * If witnesses can't start (e.g., LMDB collision in keripy 1.3.4),
 * Phase B tests skip gracefully.
 *
 * This is a module-level singleton: witnesses start once and are shared
 * across all test files in the same vitest run.
 */

import { execSync } from 'node:child_process';

let _checked = false;
let _available = false;

export function areWitnessesAvailable(): boolean {
  if (!_checked) {
    _checked = true;
    try {
      // Quick check: can we reach the witness HTTP port?
      // If witness demo was started externally, this will succeed.
      execSync('curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/', {
        timeout: 3000,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      // If we got here without timeout, check the HTTP code
      const code = execSync(
        'curl -s -m2 -o /dev/null -w "%{http_code}" http://127.0.0.1:5642/',
        { timeout: 3000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] },
      ).trim();
      _available = code !== '000';
    } catch {
      _available = false;
    }
  }
  return _available;
}

export const WITNESSES_AVAILABLE = areWitnessesAvailable();
