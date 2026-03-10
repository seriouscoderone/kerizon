import { base64urlEncode, base64urlDecode } from './codec.js';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function intToB64(value: number, length: number): string {
  let v = value;
  let out = '';
  do {
    out = B64[v & 63] + out;
    v = Math.floor(v / 64);
  } while (v > 0);
  return out.padStart(length, 'A');
}

function b64ToInt(text: string): number {
  let out = 0;
  for (const ch of text) {
    out = out * 64 + B64.indexOf(ch);
  }
  return out;
}

export interface IndexedCodeEntry {
  readonly code: string;
  readonly description: string;
  readonly hardSize: number;
  readonly softSize: number;
  readonly ondexSize: number;
  readonly fullSize: number;
  readonly leadSize: number;
}

export const INDEXED_CODE_TABLE: readonly IndexedCodeEntry[] = [
  { code: 'A', description: 'Ed25519 indexed sig, current only', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: 'B', description: 'Ed25519 indexed sig, both same', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: 'C', description: 'ECDSA-256k1 indexed sig, current only', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: 'D', description: 'ECDSA-256k1 indexed sig, both same', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: 'E', description: 'Ed448 indexed sig, current only', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: 'F', description: 'Ed448 indexed sig, both same', hardSize: 1, softSize: 1, ondexSize: 0, fullSize: 88, leadSize: 0 },
  { code: '0A', description: 'Ed25519 indexed sig, current only, big', hardSize: 2, softSize: 2, ondexSize: 1, fullSize: 156, leadSize: 0 },
  { code: '0B', description: 'Ed25519 indexed sig, both same, big', hardSize: 2, softSize: 2, ondexSize: 1, fullSize: 156, leadSize: 0 },
];

const INDEXED_LOOKUP = new Map<string, IndexedCodeEntry>(
  INDEXED_CODE_TABLE.map(e => [e.code, e] as const)
);

function indexerHardSize(firstChar: string): number {
  return (firstChar === '0' || firstChar === '1' || firstChar === '2' ||
          firstChar === '3' || firstChar === '4') ? 2 : 1;
}

export class Indexer {
  readonly code: string;
  readonly raw: Uint8Array;
  readonly index: number;
  readonly ondex: number;

  constructor(opts:
    | { code: string; raw: Uint8Array; index: number; ondex?: number }
    | { qb64: string }
    | { qb64b: Uint8Array }
  ) {
    if ('code' in opts && 'raw' in opts) {
      const entry = INDEXED_LOOKUP.get(opts.code);
      if (!entry) throw new Error(`Unknown indexer code: ${opts.code}`);
      this.code = opts.code;
      this.raw = opts.raw;
      this.index = opts.index;
      this.ondex = opts.ondex ?? opts.index;
    } else if ('qb64' in opts) {
      const parsed = parseIndexerQb64(opts.qb64);
      this.code = parsed.code;
      this.raw = parsed.raw;
      this.index = parsed.index;
      this.ondex = parsed.ondex;
    } else {
      const qb64 = String.fromCharCode(...opts.qb64b);
      const parsed = parseIndexerQb64(qb64);
      this.code = parsed.code;
      this.raw = parsed.raw;
      this.index = parsed.index;
      this.ondex = parsed.ondex;
    }
  }

  get qb64(): string {
    const entry = INDEXED_LOOKUP.get(this.code)!;
    const { hardSize: hs, softSize: ss, ondexSize: os } = entry;
    let soft: string;
    if (os > 0) {
      soft = intToB64(this.ondex, os) + intToB64(this.index, ss - os);
    } else {
      soft = intToB64(this.index, ss);
    }
    const body = base64urlEncode(this.raw);
    return this.code + soft + body;
  }

  get qb64b(): Uint8Array {
    return new TextEncoder().encode(this.qb64);
  }

  get fullSize(): number {
    return INDEXED_LOOKUP.get(this.code)!.fullSize;
  }
}

function parseIndexerQb64(text: string): { code: string; raw: Uint8Array; index: number; ondex: number } {
  const hs = indexerHardSize(text[0]);
  const code = text.slice(0, hs);
  const entry = INDEXED_LOOKUP.get(code);
  if (!entry) throw new Error(`Unknown indexer code: ${code}`);
  const { softSize: ss, ondexSize: os, fullSize: fs, leadSize: ls } = entry;
  const cs = hs + ss;
  const soft = text.slice(hs, cs);

  let index: number;
  let ondex: number;
  if (os > 0) {
    ondex = b64ToInt(soft.slice(0, os));
    index = b64ToInt(soft.slice(os));
  } else {
    index = b64ToInt(soft);
    ondex = index;
  }

  const raw = base64urlDecode(text.slice(cs, fs)).slice(ls);
  return { code, raw, index, ondex };
}

export function parseIndexerFromText(input: Uint8Array): Indexer {
  const qb64 = String.fromCharCode(...input);
  return new Indexer({ qb64 });
}

export { INDEXED_LOOKUP, intToB64, b64ToInt };
