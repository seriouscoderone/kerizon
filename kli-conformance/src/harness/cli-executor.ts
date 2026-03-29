/**
 * Subprocess executor for CLI commands.
 * Spawns the CLI as a child process, captures stdout/stderr, enforces timeouts.
 */

import { spawn } from 'node:child_process';
import type { CliResult } from '../adapter/types.js';

export interface ExecOptions {
  /** Timeout in milliseconds (default: 30_000) */
  timeout?: number;
  /** Data to pipe to stdin */
  stdin?: Uint8Array | string;
  /** Extra environment variables */
  env?: Record<string, string>;
  /** Working directory */
  cwd?: string;
}

/**
 * Execute a CLI command and capture output.
 *
 * Uses spawn (not exec) for streaming large CESR outputs.
 * Returns structured CliResult with exit code, stdout, stderr, duration.
 */
export function execCli(
  command: string,
  args: string[],
  opts: ExecOptions = {},
): Promise<CliResult> {
  const timeout = opts.timeout ?? 30_000;

  return new Promise((resolve, reject) => {
    const start = performance.now();

    const proc = spawn(command, args, {
      cwd: opts.cwd,
      env: {
        ...process.env,
        DYLD_FALLBACK_LIBRARY_PATH: '/opt/homebrew/lib',
        ...opts.env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    proc.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    if (opts.stdin != null) {
      proc.stdin.write(opts.stdin);
      proc.stdin.end();
    } else {
      proc.stdin.end();
    }

    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      setTimeout(() => {
        if (!proc.killed) proc.kill('SIGKILL');
      }, 2000);
    }, timeout);

    proc.on('close', (code, signal) => {
      clearTimeout(timer);
      const durationMs = performance.now() - start;

      resolve({
        exitCode: code ?? (signal ? 128 : -1),
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
        durationMs,
      });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Execute a CLI command, returning raw stdout as a Buffer (for CESR binary streams).
 */
export function execCliBinary(
  command: string,
  args: string[],
  opts: ExecOptions = {},
): Promise<CliResult & { stdoutBuffer: Buffer }> {
  const timeout = opts.timeout ?? 30_000;

  return new Promise((resolve, reject) => {
    const start = performance.now();

    const proc = spawn(command, args, {
      cwd: opts.cwd,
      env: {
        ...process.env,
        DYLD_FALLBACK_LIBRARY_PATH: '/opt/homebrew/lib',
        ...opts.env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    proc.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    if (opts.stdin != null) {
      proc.stdin.write(opts.stdin);
      proc.stdin.end();
    } else {
      proc.stdin.end();
    }

    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      setTimeout(() => {
        if (!proc.killed) proc.kill('SIGKILL');
      }, 2000);
    }, timeout);

    proc.on('close', (code, signal) => {
      clearTimeout(timer);
      const durationMs = performance.now() - start;
      const stdoutBuffer = Buffer.concat(stdoutChunks);

      resolve({
        exitCode: code ?? (signal ? 128 : -1),
        stdout: stdoutBuffer.toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
        durationMs,
        stdoutBuffer,
      });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}
