/**
 * Parse kli CLI output into structured types.
 *
 * Output formats extracted from keripy source:
 *   /Users/seriouscoderone/code/keripy/src/keri/cli/commands/
 *   /Users/seriouscoderone/code/keripy/src/keri/cli/common/displaying.py
 */

import type { KeyState, EventType } from '../adapter/types.js';

/**
 * Parse the prefix from incept/rotate/interact output.
 * Format: "Prefix  <pre>" (two spaces between label and value)
 */
export function parsePrefix(stdout: string): string | undefined {
  const match = stdout.match(/^Prefix\s{2,}(\S+)/m);
  return match?.[1];
}

/**
 * Parse the sequence number from rotate/interact output.
 * Format: "New Sequence No.  <sn>"
 */
export function parseNewSeqNo(stdout: string): number | undefined {
  const match = stdout.match(/^New Sequence No\.\s{2,}(\d+)/m);
  return match ? parseInt(match[1], 10) : undefined;
}

/**
 * Parse public keys from incept/rotate/interact output.
 * Format: "\tPublic key N:  <qb64>"
 */
export function parsePublicKeys(stdout: string): string[] {
  const keys: string[] = [];
  const regex = /^\tPublic key \d+:\s{2,}(\S+)/gm;
  let match;
  while ((match = regex.exec(stdout)) !== null) {
    keys.push(match[1]);
  }
  return keys;
}

/**
 * Parse signatures from sign output.
 * Format: "N. <siger.qb64>" (1-indexed)
 */
export function parseSignatures(stdout: string): string[] {
  const sigs: string[] = [];
  const regex = /^\d+\.\s+(\S+)/gm;
  let match;
  while ((match = regex.exec(stdout)) !== null) {
    sigs.push(match[1]);
  }
  return sigs;
}

/**
 * Parse verify result from verify output.
 * Success: "Signature N is valid."
 * Failure: non-zero exit code or "invalid" in stderr
 */
export function parseVerifyResult(stdout: string, exitCode: number): boolean {
  if (exitCode !== 0) return false;
  return /Signature \d+ is valid/m.test(stdout);
}

/**
 * Parse identifier list from list output.
 * Format: "<name> (<pre>)"
 */
export function parseIdentifierList(stdout: string): Array<{ name: string; prefix: string }> {
  const entries: Array<{ name: string; prefix: string }> = [];
  const regex = /^(.+?)\s+\((\S+)\)/gm;
  let match;
  while ((match = regex.exec(stdout)) !== null) {
    entries.push({ name: match[1].trim(), prefix: match[2] });
  }
  return entries;
}

/**
 * Parse OOBI URLs from oobi generate output.
 * One URL per line.
 */
export function parseOobiUrls(stdout: string): string[] {
  return stdout
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.startsWith('http'));
}

/**
 * Parse key state from status output.
 * Format (from displaying.printIdentifier):
 *   Alias:      <name>
 *   Identifier: <pre>
 *   Seq No:     <sn>
 *   Delegated Identifier (optional)
 *       Delegator:  <delpre>
 *   Witnesses:
 *     Count:      <N>
 *     Receipts:   <N>
 *     Threshold:  <N>
 *   Public Keys:
 *     1. <qb64>
 */
export function parseKeyState(stdout: string): KeyState | undefined {
  const prefixMatch = stdout.match(/^Identifier:\s*(\S+)/m);
  if (!prefixMatch) return undefined;

  const snMatch = stdout.match(/^Seq No:\s*(\d+)/m);
  const thresholdMatch = stdout.match(/^\s*Threshold:\s*(\d+)/m);
  const delegatorMatch = stdout.match(/^\s{4}Delegator:\s*(\S+)/m);

  // Parse public keys (numbered list)
  const keys: string[] = [];
  const keyRegex = /^\s+\d+\.\s+(\S+)/gm;
  let km;
  while ((km = keyRegex.exec(stdout)) !== null) {
    keys.push(km[1]);
  }

  // Parse witnesses from verbose output if available
  const backers: string[] = [];
  const witRegex = /^\s+\d+\.\s+(B\S{43})/gm;
  // Witnesses section comes before Public Keys
  const witnessSection = stdout.split('Public Keys:')[0];
  if (witnessSection) {
    let wm;
    const witSectionRegex = /^\s+\d+\.\s+(B\S{43})/gm;
    while ((wm = witSectionRegex.exec(witnessSection)) !== null) {
      backers.push(wm[1]);
    }
  }

  return {
    prefix: prefixMatch[1],
    sn: snMatch ? parseInt(snMatch[1], 10) : 0,
    currentKeys: keys,
    currentThreshold: '1',
    nextKeyDigests: [],
    nextThreshold: '1',
    backers,
    backerThreshold: thresholdMatch ? parseInt(thresholdMatch[1], 10) : 0,
    lastEventDigest: '',
    delegator: delegatorMatch?.[1],
    configTraits: [],
    transferable: true,
  };
}

/**
 * Parse verbose status output to extract individual KEL events as JSON.
 * When --verbose is used, status prints pretty-printed JSON for each event.
 */
export function parseVerboseEvents(stdout: string): Array<Record<string, unknown>> {
  const events: Array<Record<string, unknown>> = [];
  // Find JSON blocks - they start with { and end with } at the same indent
  const jsonRegex = /^\{[\s\S]*?^\}/gm;
  let match;
  while ((match = jsonRegex.exec(stdout)) !== null) {
    try {
      events.push(JSON.parse(match[0]));
    } catch {
      // skip malformed blocks
    }
  }
  return events;
}

/**
 * Parse event output from `kli event` command.
 */
export function parseEventOutput(stdout: string, flags: {
  said?: boolean;
  sn?: boolean;
  raw?: boolean;
  json?: boolean;
  seal?: boolean;
}): {
  said?: string;
  sn?: number;
  raw?: string;
  json?: Record<string, unknown>;
  seal?: { i: string; s: string; d: string };
} {
  const result: ReturnType<typeof parseEventOutput> = {};

  const trimmed = stdout.trim();

  if (flags.said) {
    result.said = trimmed.split('\n')[0]?.trim();
  }

  if (flags.sn) {
    result.sn = parseInt(trimmed.split('\n')[0]?.trim() ?? '0', 10);
  }

  if (flags.raw) {
    result.raw = trimmed;
  }

  if (flags.json) {
    try {
      result.json = JSON.parse(trimmed);
    } catch { /* ignore */ }
  }

  if (flags.seal) {
    try {
      result.seal = JSON.parse(trimmed);
    } catch { /* ignore */ }
  }

  return result;
}
