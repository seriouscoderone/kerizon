import {
  CODE_TABLE,
  type CodeEntry,
  base64urlEncode,
  base64urlDecode,
  padSize,
  selectorDispatch,
  textSize,
} from './codec.js';

const MATTER_TABLE = CODE_TABLE.filter(e => e.category !== 'indexed-signature');
const MATTER_LOOKUP = new Map<string, CodeEntry>(
  MATTER_TABLE.map(e => [e.code, e] as const)
);

export class Matter {
  readonly code: string;
  readonly raw: Uint8Array;

  constructor(opts: { code: string; raw: Uint8Array } | { qb64: string } | { qb64b: Uint8Array }) {
    if ('code' in opts && 'raw' in opts) {
      const entry = MATTER_LOOKUP.get(opts.code);
      if (!entry) throw new Error(`Unknown matter code: ${opts.code}`);
      if (opts.raw.length !== entry.rawSize)
        throw new Error(`Raw size ${opts.raw.length} !== expected ${entry.rawSize} for code ${opts.code}`);
      this.code = opts.code;
      this.raw = opts.raw;
    } else if ('qb64' in opts) {
      const parsed = parseMatterQb64(opts.qb64);
      this.code = parsed.code;
      this.raw = parsed.raw;
    } else {
      const qb64 = String.fromCharCode(...opts.qb64b);
      const parsed = parseMatterQb64(qb64);
      this.code = parsed.code;
      this.raw = parsed.raw;
    }
  }

  get qb64(): string {
    const ps = padSize(this.code, this.raw.length);
    const padded = new Uint8Array(ps + this.raw.length);
    padded.set(this.raw, ps);
    const encoded = base64urlEncode(padded);
    return this.code + encoded.slice(this.code.length);
  }

  get qb64b(): Uint8Array {
    return new TextEncoder().encode(this.qb64);
  }

  get qb2(): Uint8Array {
    return base64urlDecode(this.qb64);
  }

  get fullSize(): number {
    return textSize(this.code, this.raw.length);
  }
}

function parseMatterQb64(text: string): { code: string; raw: Uint8Array } {
  const cs = selectorDispatch(text[0]);
  const code = text.slice(0, cs);
  const entry = MATTER_LOOKUP.get(code);
  if (!entry) throw new Error(`Unknown matter code: ${code}`);
  const ps = padSize(code, entry.rawSize);
  const restored = 'A'.repeat(cs) + text.slice(cs);
  const padded = base64urlDecode(restored);
  const raw = padded.slice(ps);
  return { code, raw };
}

export function parseMatterFromText(input: Uint8Array): Matter {
  const qb64 = String.fromCharCode(...input);
  return new Matter({ qb64 });
}

export { MATTER_TABLE, MATTER_LOOKUP };
