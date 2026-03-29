/**
 * kerizon adapter — translates the CliAdapter interface to kerizon CLI commands.
 *
 * Mirrors the KliAdapter pattern but calls `kerizon` (or `node dist/cli.js`)
 * instead of `kli`. Output format matches kli, so the same result-parser
 * functions work for both.
 */

import { resolve } from 'node:path';
import type {
  CliAdapter,
  CliResult,
  KeyState,
  KelEvent,
  InceptConfig,
  RotateConfig,
  InteractConfig,
  WitnessHandle,
} from './types.js';
import { execCli, execCliBinary } from '../harness/cli-executor.js';
import { createTempEnv, type TempEnv } from '../harness/temp-env.js';
import {
  parsePrefix,
  parseNewSeqNo,
  parsePublicKeys,
  parseSignatures,
  parseVerifyResult,
  parseKeyState,
  parseVerboseEvents,
  parseIdentifierList,
  parseEventOutput,
} from '../harness/result-parser.js';

export interface KerizonAdapterOptions {
  /** Path to the kerizon executable or node script (default: "kerizon") */
  cliPath?: string;
  /**
   * If true, run via `node <cliPath>` instead of directly.
   * Useful for testing against the un-installed dist/cli.js.
   */
  useNode?: boolean;
  /** Keystore name used for all commands. Use unique names for test isolation. */
  keystoreName: string;
  /** Command timeout in ms (default: 30_000) */
  timeout?: number;
}

export class KerizonAdapter implements CliAdapter {
  readonly name = 'kerizon';
  readonly version = '0.1.0';

  private readonly cliPath: string;
  private readonly useNode: boolean;
  private readonly keystoreName: string;
  private readonly timeout: number;
  private tempEnv?: TempEnv;

  constructor(opts: KerizonAdapterOptions) {
    this.cliPath = opts.cliPath ?? 'kerizon';
    this.useNode = opts.useNode ?? false;
    this.keystoreName = opts.keystoreName;
    this.timeout = opts.timeout ?? 30_000;
  }

  private async ensureTempEnv(): Promise<TempEnv> {
    if (!this.tempEnv) {
      this.tempEnv = await createTempEnv('kerizon-adapter-');
    }
    return this.tempEnv;
  }

  private run(args: string[]): Promise<CliResult> {
    // cwd must be the kerizon-cli package dir so node resolves file: dependencies
    const cwd = this.useNode ? resolve(this.cliPath, '../..') : undefined;
    if (this.useNode) {
      return execCli('node', [this.cliPath, ...args], { timeout: this.timeout, cwd });
    }
    return execCli(this.cliPath, args, { timeout: this.timeout, cwd });
  }

  private runBinary(args: string[]) {
    const cwd = this.useNode ? resolve(this.cliPath, '../..') : undefined;
    if (this.useNode) {
      return execCliBinary('node', [this.cliPath, ...args], { timeout: this.timeout, cwd });
    }
    return execCliBinary(this.cliPath, args, { timeout: this.timeout, cwd });
  }

  private keystoreArgs(): string[] {
    return ['--name', this.keystoreName];
  }

  // ── Lifecycle ──

  async init(opts: {
    name: string;
    salt?: string;
    passcode?: string;
    nopasscode?: boolean;
    tempDir?: string;
  }): Promise<CliResult> {
    const args = ['init', '--name', opts.name];
    if (opts.nopasscode) args.push('--nopasscode');
    return this.run(args);
  }

  async destroy(_opts: { name: string }): Promise<CliResult> {
    // kerizon doesn't have a destroy command; store files are in ~/.kerizon/
    return { exitCode: 0, stdout: '', stderr: '', durationMs: 0 };
  }

  // ── Identifier operations ──

  async incept(config: InceptConfig): Promise<CliResult & { prefix?: string }> {
    const args = ['incept', ...this.keystoreArgs(), '--alias', config.alias];

    if (config.transferable !== false) args.push('--transferable');
    if (config.signingKeyCount != null) args.push('--icount', String(config.signingKeyCount));
    if (config.nextKeyCount != null) args.push('--ncount', String(config.nextKeyCount));
    if (config.signingThreshold) args.push('--isith', config.signingThreshold);
    if (config.nextThreshold) args.push('--nsith', config.nextThreshold);
    if (config.establishmentOnly) args.push('--est-only');
    if (config.delegator) args.push('--delpre', config.delegator);

    const result = await this.run(args);
    const prefix = parsePrefix(result.stdout);
    return { ...result, prefix };
  }

  async rotate(config: RotateConfig): Promise<CliResult> {
    const args = ['rotate', ...this.keystoreArgs(), '--alias', config.alias];
    return this.run(args);
  }

  async interact(config: InteractConfig): Promise<CliResult> {
    const args = ['interact', ...this.keystoreArgs(), '--alias', config.alias];
    if (config.data) {
      args.push('--data', JSON.stringify(config.data));
    }
    return this.run(args);
  }

  async status(alias: string): Promise<CliResult & { keyState?: KeyState }> {
    const args = ['status', ...this.keystoreArgs(), '--alias', alias, '--verbose'];
    const result = await this.run(args);
    const keyState = parseKeyState(result.stdout);
    return { ...result, keyState };
  }

  // ── KEL operations ──

  async exportKel(alias: string): Promise<CliResult & { cesr?: Uint8Array }> {
    const args = ['export', ...this.keystoreArgs(), '--alias', alias];
    const result = await this.runBinary(args);
    const cesr = result.exitCode === 0 ? new Uint8Array(result.stdoutBuffer) : undefined;
    return { ...result, cesr };
  }

  async importKel(cesrBytes: Uint8Array): Promise<CliResult> {
    const tempEnv = await this.ensureTempEnv();
    const cesrPath = await tempEnv.writeBinary('import.cesr', cesrBytes);
    return this.run(['import', ...this.keystoreArgs(), '--file', cesrPath]);
  }

  async exportEvents(alias: string): Promise<CliResult & { events?: KelEvent[] }> {
    const args = ['status', ...this.keystoreArgs(), '--alias', alias, '--verbose'];
    const result = await this.run(args);
    if (result.exitCode !== 0) return { ...result, events: undefined };

    const rawEvents = parseVerboseEvents(result.stdout);
    const events: KelEvent[] = rawEvents.map(raw => ({
      version: raw['v'] as string ?? '',
      type: raw['t'] as KelEvent['type'] ?? 'icp',
      said: raw['d'] as string ?? '',
      prefix: raw['i'] as string ?? '',
      sn: typeof raw['s'] === 'string' ? parseInt(raw['s'], 16) : (raw['s'] as number ?? 0),
      priorDigest: raw['p'] as string | undefined,
      raw: JSON.stringify(raw),
      cesr: new Uint8Array(),
    }));

    return { ...result, events };
  }

  // ── Signing ──

  async sign(alias: string, text: string): Promise<CliResult & { signatures?: string[] }> {
    const args = ['sign', ...this.keystoreArgs(), '--alias', alias, '--text', text];
    const result = await this.run(args);
    const signatures = result.exitCode === 0 ? parseSignatures(result.stdout) : undefined;
    return { ...result, signatures };
  }

  async verify(
    prefix: string,
    text: string,
    signatures: string[],
  ): Promise<CliResult & { valid?: boolean }> {
    const args = ['verify', ...this.keystoreArgs(), '--prefix', prefix, '--text', text];
    for (const sig of signatures) {
      args.push('--signature', sig);
    }
    const result = await this.run(args);
    const valid = parseVerifyResult(result.stdout, result.exitCode);
    return { ...result, valid };
  }

  // ── OOBI ──

  async oobiGenerate(_alias: string, _role: string): Promise<CliResult & { oobis?: string[] }> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async oobiResolve(_oobi: string, _alias?: string): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  // ── Event inspection ──

  async event(alias: string, flags: {
    said?: boolean; sn?: boolean; raw?: boolean; json?: boolean; seal?: boolean;
  }): Promise<CliResult & {
    said?: string; sn?: number; raw?: string;
    json?: Record<string, unknown>;
    seal?: { i: string; s: string; d: string };
  }> {
    const args = ['event', ...this.keystoreArgs(), '--alias', alias];
    if (flags.said) args.push('--said');
    if (flags.sn) args.push('--sn');
    if (flags.raw) args.push('--raw');
    if (flags.json) args.push('--json');
    if (flags.seal) args.push('--seal');

    const result = await this.run(args);
    const parsed = parseEventOutput(result.stdout, flags);
    return { ...result, ...parsed };
  }

  async list(): Promise<CliResult & { identifiers?: Array<{ name: string; prefix: string }> }> {
    const args = ['list', ...this.keystoreArgs()];
    const result = await this.run(args);
    const identifiers = result.exitCode === 0 ? parseIdentifierList(result.stdout) : undefined;
    return { ...result, identifiers };
  }

  // ── Credential lifecycle (not implemented) ──

  async vcRegistryIncept(_alias: string, _registryName: string): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async vcCreate(_opts: {
    alias: string; registryName: string; schema: string;
    data: Record<string, unknown>; recipient?: string;
  }): Promise<CliResult & { said?: string }> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async vcList(_alias: string): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async vcRevoke(_alias: string, _said: string): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  // ── Challenge-response (not implemented) ──

  async challengeGenerate(_strength?: number): Promise<CliResult & { words?: string[] }> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async challengeRespond(_opts: {
    alias: string; recipient: string; words: string;
  }): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  async challengeVerify(_opts: {
    alias: string; signer: string; words: string;
  }): Promise<CliResult & { verified?: boolean }> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  // ── Delegation (not implemented) ──

  async delegateConfirm(_alias: string, _opts?: {
    auto?: boolean; interact?: boolean;
  }): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  // ── Escrow (not implemented) ──

  async escrowList(): Promise<CliResult> {
    return { exitCode: 1, stdout: '', stderr: 'Not implemented', durationMs: 0 };
  }

  // ── Witnesses (not implemented) ──

  async witnessDemo(): Promise<WitnessHandle> {
    throw new Error('Witness demo not supported by kerizon CLI');
  }
}
