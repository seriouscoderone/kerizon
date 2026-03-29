/**
 * CLI integration tests — exercises the built kerizon CLI via execSync.
 *
 * These tests run against the compiled dist/cli.js and verify output format
 * matches what the kli-conformance harness result-parser expects.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';

const CLI = join(import.meta.dirname, '..', 'dist', 'cli.js');
const TEST_NAME = `cli-test-${randomBytes(4).toString('hex')}`;

function run(args: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execSync(`node ${CLI} ${args}`, {
      encoding: 'utf-8',
      timeout: 30_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
      exitCode: err.status ?? 1,
    };
  }
}

describe('kerizon CLI', () => {
  beforeAll(() => {
    // Ensure build is up to date (caller should have built already)
    if (!existsSync(CLI)) {
      throw new Error(`CLI not built at ${CLI}. Run: npm run build`);
    }
  });

  afterAll(() => {
    // Clean up test keystore
    const dir = join(homedir(), '.kerizon', TEST_NAME);
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('version: outputs library version', () => {
    const { stdout, exitCode } = run('version');
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Library version: 0.1.0');
  });

  it('init: creates keystore', () => {
    const { stdout, exitCode } = run(`init --name ${TEST_NAME} --nopasscode`);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('KERI Keystore created at:');
  });

  it('incept: creates transferable identifier', () => {
    const { stdout, exitCode } = run(
      `incept --name ${TEST_NAME} --alias alice --transferable`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Prefix\s{2,}\S+/m);
    expect(stdout).toMatch(/^\tPublic key 1:\s{2,}\S+/m);
  });

  it('status: shows key state', () => {
    const { stdout, exitCode } = run(
      `status --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Alias:\talice/m);
    expect(stdout).toMatch(/^Identifier:\s+\S+/m);
    expect(stdout).toMatch(/^Seq No:\t0/m);
    expect(stdout).toMatch(/^\t1\.\s+\S+/m);
  });

  it('rotate: increments sequence number', () => {
    const { stdout, exitCode } = run(
      `rotate --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Prefix\s{2,}\S+/m);
    expect(stdout).toMatch(/^New Sequence No\.\s{2,}1/m);
    expect(stdout).toMatch(/^\tPublic key 1:\s{2,}\S+/m);
  });

  it('interact: creates interaction event', () => {
    const { stdout, exitCode } = run(
      `interact --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Prefix\s{2,}\S+/m);
    expect(stdout).toMatch(/^New Sequence No\.\s{2,}2/m);
  });

  it('sign: produces indexed signature', () => {
    const { stdout, exitCode } = run(
      `sign --name ${TEST_NAME} --alias alice --text hello`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^1\.\s+\S+/m);

    // Extract signature qb64 — should be parseable
    const sig = stdout.match(/^1\.\s+(\S+)/m)?.[1];
    expect(sig).toBeTruthy();
    expect(sig!.startsWith('A')).toBe(true); // Ed25519_Sig code
  });

  it('verify: validates signature', () => {
    // Sign first
    const signResult = run(
      `sign --name ${TEST_NAME} --alias alice --text testmsg`,
    );
    expect(signResult.exitCode).toBe(0);
    const sig = signResult.stdout.match(/^1\.\s+(\S+)/m)?.[1];
    expect(sig).toBeTruthy();

    // Get prefix
    const statusResult = run(
      `status --name ${TEST_NAME} --alias alice`,
    );
    const prefix = statusResult.stdout.match(/^Identifier:\s+(\S+)/m)?.[1];
    expect(prefix).toBeTruthy();

    // Verify
    const { stdout, exitCode } = run(
      `verify --name ${TEST_NAME} --prefix ${prefix} --text testmsg --signature ${sig}`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Signature 1 is valid.');
  });

  it('verify: rejects bad signature', () => {
    // Get prefix
    const statusResult = run(
      `status --name ${TEST_NAME} --alias alice`,
    );
    const prefix = statusResult.stdout.match(/^Identifier:\s+(\S+)/m)?.[1];
    expect(prefix).toBeTruthy();

    // Use a valid-format but wrong signature (88 chars starting with 'AA')
    const badSig = 'AA' + 'A'.repeat(86);
    const { exitCode } = run(
      `verify --name ${TEST_NAME} --prefix ${prefix} --text hello --signature ${badSig}`,
    );
    expect(exitCode).toBe(1);
  });

  it('list: shows identifiers', () => {
    const { stdout, exitCode } = run(`list --name ${TEST_NAME}`);
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^alice\s+\(\S+\)/m);
  });

  it('event --said: outputs last event SAID', () => {
    const { stdout, exitCode } = run(
      `event --name ${TEST_NAME} --alias alice --said`,
    );
    expect(exitCode).toBe(0);
    const said = stdout.trim();
    // SAIDs start with 'E' (Blake3-256 code)
    expect(said.startsWith('E')).toBe(true);
    expect(said.length).toBe(44);
  });

  it('event --sn: outputs last event sequence number', () => {
    const { stdout, exitCode } = run(
      `event --name ${TEST_NAME} --alias alice --sn`,
    );
    expect(exitCode).toBe(0);
    expect(parseInt(stdout.trim(), 10)).toBe(2);
  });

  it('export: outputs CESR stream', () => {
    const { stdout, exitCode } = run(
      `export --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    // Should contain icp event followed by attachment
    expect(stdout).toContain('"t":"icp"');
    expect(stdout).toContain('-A');
  });

  it('incept: creates second identifier', () => {
    const { stdout, exitCode } = run(
      `incept --name ${TEST_NAME} --alias bob --transferable`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Prefix\s{2,}\S+/m);
  });

  it('list: shows both identifiers', () => {
    const { stdout, exitCode } = run(`list --name ${TEST_NAME}`);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('alice');
    expect(stdout).toContain('bob');
  });

  it('incept with --est-only: blocks interaction events', () => {
    run(`incept --name ${TEST_NAME} --alias carol --transferable --est-only`);

    const { exitCode, stderr } = run(
      `interact --name ${TEST_NAME} --alias carol`,
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Establishment-only');
  });

  it('second rotate: works correctly', () => {
    const { stdout, exitCode } = run(
      `rotate --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^New Sequence No\.\s{2,}3/m);
  });

  it('status after multiple events: shows correct sn', () => {
    const { stdout, exitCode } = run(
      `status --name ${TEST_NAME} --alias alice`,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/^Seq No:\t3/m);
  });
});
