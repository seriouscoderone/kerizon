import { COUNTER_TABLE, type CounterEntry, counterTextSize } from './codec.js';

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

const COUNTER_LOOKUP = new Map<string, CounterEntry>(
  COUNTER_TABLE.map(e => [e.code, e] as const)
);

const COUNTER_NAMES: Record<string, string> = {
  '-A': 'ControllerIdxSigs',
  '-B': 'WitnessIdxSigs',
  '-C': 'NonTransReceiptCouples',
  '-D': 'TransIndexedSigGroups',
  '-E': 'TransLastIdxSigGroups',
  '-F': 'FirstSeenReplayCouples',
  '-V': 'AttachedMaterialQuadlets',
};

export class Counter {
  readonly code: string;
  readonly count: number;
  readonly name: string;

  constructor(opts: { code: string; count: number } | { qb64: string } | { qb64b: Uint8Array }) {
    if ('code' in opts && 'count' in opts) {
      this.code = opts.code;
      this.count = opts.count;
    } else if ('qb64' in opts) {
      const parsed = parseCounterQb64(opts.qb64);
      this.code = parsed.code;
      this.count = parsed.count;
    } else {
      const qb64 = String.fromCharCode(...opts.qb64b);
      const parsed = parseCounterQb64(qb64);
      this.code = parsed.code;
      this.count = parsed.count;
    }
    this.name = COUNTER_NAMES[this.code] ?? this.code;
  }

  get qb64(): string {
    const countChars = counterTextSize(this.code) - this.code.length;
    return this.code + intToB64(this.count, countChars);
  }

  get qb64b(): Uint8Array {
    return new TextEncoder().encode(this.qb64);
  }

  get fullSize(): number {
    return counterTextSize(this.code);
  }
}

function parseCounterQb64(text: string): { code: string; count: number } {
  if (text[0] !== '-') throw new Error(`Not a counter code: ${text[0]}`);
  const code = text.slice(0, 2);
  const countChars = counterTextSize(code) - code.length;
  const count = b64ToInt(text.slice(2, 2 + countChars));
  return { code, count };
}

export function parseCounterFromText(input: Uint8Array): Counter {
  const qb64 = String.fromCharCode(...input);
  return new Counter({ qb64 });
}

export { COUNTER_LOOKUP, COUNTER_NAMES };
