import { Matter } from './primitives/matter.js';

export function encode(code: string, raw: Uint8Array): string {
  return new Matter({ code, raw }).qb64;
}

export function decode(qb64: string): { code: string; raw: Uint8Array } {
  const m = new Matter({ qb64 });
  return { code: m.code, raw: m.raw };
}

export type SerializationKind = 'JSON' | 'CBOR' | 'MGPK' | 'CESR' | null;

// Cold-start tritet dispatch (first byte >> 5):
//   3=JSON, 4=MGPK FixMap, 5=CBOR, 6=MGPK Map16/32, 1/2/7=CESR, 0=CESR annotated
export function sniff(data: Uint8Array): SerializationKind {
  if (data.length === 0) return null;
  const tritet = data[0] >> 5;
  switch (tritet) {
    case 3: return 'JSON';
    case 4: return 'MGPK';
    case 5: return 'CBOR';
    case 6: return 'MGPK';
    case 1: case 2: case 7: case 0: return 'CESR';
    default: return null;
  }
}
