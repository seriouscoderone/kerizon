/**
 * Synchronous kli detection for test skipIf conditions.
 * This runs at module load time so skipIf can use the result.
 */

import { execSync } from 'node:child_process';

let _kliAvailable: boolean | null = null;

export function isKliAvailable(): boolean {
  if (_kliAvailable === null) {
    try {
      const result = execSync('kli version', {
        timeout: 5000,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, DYLD_FALLBACK_LIBRARY_PATH: '/opt/homebrew/lib' },
      });
      _kliAvailable = result.includes('Library version');
    } catch {
      _kliAvailable = false;
    }
  }
  return _kliAvailable;
}

export const KLI_AVAILABLE = isKliAvailable();
