/**
 * CESR stream parser.
 *
 * Parses a concatenated CESR stream (e.g. from `kli export` or `kerizon export`)
 * into individual messages. Each message consists of a JSON event body followed
 * by attachment groups containing indexed signatures.
 *
 * Supports two attachment formats:
 *   - kli format: `-VAn-AABAAABg1g...`  (AttachmentGroup `-V` wrapping ControllerIdxSigs `-A`)
 *   - kerizon format: `-AABAAABnvO...`   (just ControllerIdxSigs `-A` directly)
 */

import { Serder } from './serder.js';
import { Siger } from '../primitives/siger.js';
import { b64Value } from '../primitives/matter.js';
import { CtrDex_1_0, CtrDex_2_0, IdrSizage } from '../primitives/code-table.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ParsedMessage {
  serder: Serder;
  sigers: Siger[];
}

// ---------------------------------------------------------------------------
// Counter code helpers
// ---------------------------------------------------------------------------

/** Decode two B64 chars into a count value. */
function decodeCount(ch1: string, ch2: string): number {
  return b64Value(ch1) * 64 + b64Value(ch2);
}

/**
 * Identify a counter code at `pos` in `text`.
 *
 * Returns the code string (e.g. `-A`, `-V`, `-0V`) and its total header length
 * (code + count chars), plus the decoded count.
 *
 * Short counters: `-X##` (4 chars total, 2-char code, 2-char count)
 * Big counters:   `-0X####` (8 chars total, 3-char code, 5-char count) -- not needed yet
 * Genus:          `--AAA###` (8 chars total) -- not needed yet
 */
function parseCounter(text: string, pos: number): {
  code: string;
  headerLen: number;
  count: number;
} | null {
  if (pos >= text.length || text[pos] !== '-') return null;

  // Check for big counter: -0X
  if (pos + 1 < text.length && text[pos + 1] === '-') {
    // Genus version `--AAA...` -- skip for now
    return null;
  }

  if (pos + 1 < text.length && text[pos + 1] === '0') {
    // Big counter: -0X##### (3-char code + 5-char count = 8 chars total)
    if (pos + 8 > text.length) return null;
    const code = text.substring(pos, pos + 3); // e.g. `-0V`
    // 5-char count: decode as big-endian base-64
    let count = 0;
    for (let i = 3; i < 8; i++) {
      count = count * 64 + b64Value(text[pos + i]);
    }
    return { code, headerLen: 8, count };
  }

  // Short counter: -X## (2-char code + 2-char count = 4 chars total)
  if (pos + 4 > text.length) return null;
  const code = text.substring(pos, pos + 2); // e.g. `-A`
  const count = decodeCount(text[pos + 2], text[pos + 3]);
  return { code, headerLen: 4, count };
}

// ---------------------------------------------------------------------------
// Siger extraction
// ---------------------------------------------------------------------------

/**
 * Determine the full qb64 size of the next indexed signature at `pos`.
 *
 * Looks at the first char(s) to resolve the Indexer code and its fixed size.
 */
function sigerSize(text: string, pos: number): number {
  // Try 2-char codes first (first char 0-4)
  const first = text[pos];
  if ('01234'.includes(first) && pos + 2 <= text.length) {
    const c2 = text.substring(pos, pos + 2);
    if (IdrSizage[c2]) return IdrSizage[c2].fs;
  }
  // 1-char codes
  if (IdrSizage[first]) return IdrSizage[first].fs;

  // Fallback: assume Ed25519 88-char sigs
  return 88;
}

// ---------------------------------------------------------------------------
// Controller/Witness indexed sig extraction
// ---------------------------------------------------------------------------

/** Known controller-idx-sig counter codes (v1 and v2). */
const CTRL_SIG_CODES: Set<string> = new Set([
  CtrDex_1_0.ControllerIdxSigs,   // -A
  CtrDex_2_0.ControllerIdxSigs,   // -J
]);

const WITNESS_SIG_CODES: Set<string> = new Set([
  CtrDex_1_0.WitnessIdxSigs,      // -B
  CtrDex_2_0.WitnessIdxSigs,      // -K
]);

const ATTACHMENT_GROUP_CODES: Set<string> = new Set([
  CtrDex_1_0.AttachmentGroup,      // -V
  CtrDex_2_0.AttachmentGroup,      // -C
  CtrDex_1_0.BigAttachmentGroup,   // -0V
  CtrDex_2_0.BigAttachmentGroup,   // -0C
]);

/**
 * Extract Siger instances from a region of text that contains indexed signatures.
 *
 * The `count` from the counter is in quadlets (groups of 4 chars).
 * For `-A` / `-J` counters, each quadlet-group holds one or more sigs.
 * We consume `count * 4` chars and parse as many Sigers as we can find.
 */
function extractSigers(text: string, pos: number, quadletCount: number): {
  sigers: Siger[];
  charsConsumed: number;
} {
  const totalChars = quadletCount * 4;
  const end = Math.min(pos + totalChars, text.length);
  const sigers: Siger[] = [];
  let cursor = pos;

  while (cursor < end) {
    const fs = sigerSize(text, cursor);
    if (cursor + fs > text.length) break;
    const qb64 = text.substring(cursor, cursor + fs);
    sigers.push(Siger.fromQb64(qb64));
    cursor += fs;
  }

  return { sigers, charsConsumed: totalChars };
}

// ---------------------------------------------------------------------------
// Attachment parsing
// ---------------------------------------------------------------------------

/**
 * Parse attachment groups starting at `pos`, accumulating Sigers.
 *
 * Handles both wrapped (inside `-V`) and unwrapped (direct `-A`) formats.
 * Returns the total number of characters consumed.
 */
function parseAttachments(text: string, pos: number): {
  sigers: Siger[];
  charsConsumed: number;
} {
  const sigers: Siger[] = [];
  let cursor = pos;

  while (cursor < text.length) {
    // Stop if we hit the start of a new JSON body
    if (text[cursor] === '{') break;

    // Must be a counter code
    const counter = parseCounter(text, cursor);
    if (!counter) break;

    cursor += counter.headerLen;

    if (ATTACHMENT_GROUP_CODES.has(counter.code)) {
      // AttachmentGroup wrapper: the count is in quadlets, content is nested counters
      const groupEnd = Math.min(cursor + counter.count * 4, text.length);
      while (cursor < groupEnd) {
        const inner = parseCounter(text, cursor);
        if (!inner) break;
        cursor += inner.headerLen;

        if (CTRL_SIG_CODES.has(inner.code) || WITNESS_SIG_CODES.has(inner.code)) {
          const result = extractSigers(text, cursor, inner.count);
          sigers.push(...result.sigers);
          cursor += result.charsConsumed;
        } else {
          // Unknown inner counter -- skip its quadlets
          cursor += inner.count * 4;
        }
      }
      // Ensure we advance to the group end even if inner parsing stopped early
      cursor = Math.max(cursor, groupEnd);
    } else if (CTRL_SIG_CODES.has(counter.code) || WITNESS_SIG_CODES.has(counter.code)) {
      // Direct sig group (no wrapper)
      const result = extractSigers(text, cursor, counter.count);
      sigers.push(...result.sigers);
      cursor += result.charsConsumed;
    } else {
      // Unknown counter -- skip its quadlets
      cursor += counter.count * 4;
    }
  }

  return { sigers, charsConsumed: cursor - pos };
}

// ---------------------------------------------------------------------------
// JSON body extraction
// ---------------------------------------------------------------------------

/**
 * Extract the JSON body starting at `pos` by tracking brace depth.
 * Returns the end position (exclusive) of the JSON body, or -1 on failure.
 */
function findJsonEnd(text: string, pos: number): number {
  if (text[pos] !== '{') return -1;

  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = pos; i < text.length; i++) {
    const ch = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }

  return -1;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a CESR stream (concatenated messages) into individual messages.
 *
 * Each message is a JSON body followed by attachment groups containing
 * indexed signatures. Supports both kli format (with `-V` wrapper) and
 * kerizon format (direct `-A` counter codes).
 */
export function parseStream(data: Uint8Array): ParsedMessage[] {
  const text = new TextDecoder().decode(data);
  const messages: ParsedMessage[] = [];
  let pos = 0;

  while (pos < text.length) {
    // Skip whitespace
    while (pos < text.length && (text[pos] === ' ' || text[pos] === '\n' || text[pos] === '\r' || text[pos] === '\t')) {
      pos++;
    }
    if (pos >= text.length) break;

    // Find JSON body
    if (text[pos] !== '{') {
      // Could be leading attachment garbage or unknown data -- skip one char
      pos++;
      continue;
    }

    const jsonEnd = findJsonEnd(text, pos);
    if (jsonEnd < 0) {
      throw new Error(`Unterminated JSON body at position ${pos}`);
    }

    const jsonBytes = new TextEncoder().encode(text.substring(pos, jsonEnd));
    const serder = Serder.fromRaw(jsonBytes);
    pos = jsonEnd;

    // Parse attachments after the JSON body
    const { sigers, charsConsumed } = parseAttachments(text, pos);
    pos += charsConsumed;

    messages.push({ serder, sigers });
  }

  return messages;
}
