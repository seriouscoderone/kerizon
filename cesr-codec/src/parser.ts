import { counterTextSize } from './codec.js';
import { Matter, parseMatterFromText, MATTER_LOOKUP } from './matter.js';
import { Indexer, parseIndexerFromText, INDEXED_LOOKUP } from './indexer.js';
import { Counter, COUNTER_NAMES } from './counter.js';

export type Primitive = Matter | Indexer | Counter;

export interface CesrBody {
  ked: Record<string, unknown>;
  raw: Uint8Array;
}

export interface AttachmentGroup {
  code: string;
  name: string;
  count: number;
  items: Primitive[][];
}

export interface CesrFrame {
  body: CesrBody;
  attachments: AttachmentGroup[];
}

export interface ParseEmission {
  type: 'frame' | 'error';
  frame: CesrFrame;
  error?: Error;
}

export function isPrimitiveTuple(item: unknown): item is Primitive[] {
  return Array.isArray(item) && item.length > 0 &&
    item.every(p => p instanceof Matter || p instanceof Indexer || p instanceof Counter);
}

function findJsonBodySize(bytes: Uint8Array): number {
  const text = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 512)));
  // Look for KERI/ACDC version string: {proto}{major}{minor}{kind}{size:06x}_
  const match = text.match(/[A-Z]{4}\d{2}[A-Z]{3,4}([0-9a-f]{6})_/);
  if (match) return parseInt(match[1], 16);

  // Fallback: balanced brace matching
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (escape) { escape = false; continue; }
    if (ch === 0x5C && inString) { escape = true; continue; } // backslash
    if (ch === 0x22) { inString = !inString; continue; }      // quote
    if (inString) continue;
    if (ch === 0x7B) depth++;                                   // {
    if (ch === 0x7D) { depth--; if (depth === 0) return i + 1; } // }
  }
  throw new Error('Could not determine JSON body boundary');
}

function parseAttachmentStream(text: string): AttachmentGroup[] {
  const groups: AttachmentGroup[] = [];
  let pos = 0;

  while (pos < text.length) {
    // Skip whitespace
    if (text[pos] === '\n' || text[pos] === '\r') { pos++; continue; }

    // Must start with a counter
    if (text[pos] !== '-') {
      throw new Error(`Expected counter code at position ${pos}, got '${text[pos]}'`);
    }

    const counterCode = text.slice(pos, pos + 2);
    const counterFullSize = counterTextSize(counterCode);
    const countChars = counterFullSize - 2;
    const countStr = text.slice(pos + 2, pos + 2 + countChars);
    let count = 0;
    for (const ch of countStr) {
      count = count * 64 + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(ch);
    }
    pos += counterFullSize;

    const name = COUNTER_NAMES[counterCode] ?? counterCode;
    const items: Primitive[][] = [];

    if (name === 'ControllerIdxSigs' || name === 'WitnessIdxSigs') {
      // Each item is a single indexer
      for (let i = 0; i < count; i++) {
        const entryBytes = new TextEncoder().encode(text.slice(pos));
        const indexer = parseIndexerFromText(entryBytes);
        items.push([indexer]);
        pos += indexer.fullSize;
      }
    } else if (name === 'NonTransReceiptCouples') {
      // Each item is a (verfer, cigar) pair
      for (let i = 0; i < count; i++) {
        const verferBytes = new TextEncoder().encode(text.slice(pos));
        const verfer = parseMatterFromText(verferBytes);
        pos += verfer.fullSize;
        const cigarBytes = new TextEncoder().encode(text.slice(pos));
        const cigar = parseMatterFromText(cigarBytes);
        pos += cigar.fullSize;
        items.push([verfer, cigar]);
      }
    } else if (name === 'AttachedMaterialQuadlets') {
      // Opaque quadlets: count * 4 base64 chars = count * 3 bytes
      const quadletChars = count * 4;
      pos += quadletChars;
    } else {
      // Unknown group type: try to skip based on context
      // For safety, just break to avoid infinite loops
      break;
    }

    groups.push({ code: counterCode, name, count, items });
  }

  return groups;
}

export function parseBytes(bytes: Uint8Array): ParseEmission[] {
  const emissions: ParseEmission[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    // Skip whitespace
    if (bytes[offset] === 0x0A || bytes[offset] === 0x0D || bytes[offset] === 0x20) {
      offset++;
      continue;
    }

    // If starts with '{', it's a JSON body (CESR frame)
    if (bytes[offset] === 0x7B) {
      try {
        const bodySize = findJsonBodySize(bytes.slice(offset));
        const rawBody = bytes.slice(offset, offset + bodySize);
        const jsonStr = new TextDecoder().decode(rawBody);
        const ked = JSON.parse(jsonStr) as Record<string, unknown>;
        offset += bodySize;

        // Parse remaining as attachment stream (text mode)
        const remaining = new TextDecoder().decode(bytes.slice(offset));
        const attachments = parseAttachmentStream(remaining);
        offset = bytes.length; // consume all remaining

        emissions.push({
          type: 'frame',
          frame: { body: { ked, raw: rawBody }, attachments },
        });
      } catch (e) {
        emissions.push({
          type: 'error',
          frame: undefined!,
          error: e instanceof Error ? e : new Error(String(e)),
        });
        break;
      }
    } else {
      // Bare attachment stream (no JSON body)
      break;
    }
  }

  return emissions;
}
