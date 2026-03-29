/**
 * @kerizon/cesr — Composable Event Streaming Representation primitives.
 */

export { Matter, encodeB64, decodeB64, b64Index, b64Value, resolveCode, rawSizeFromSizage } from './primitives/matter.js';
export type { MatterArgs } from './primitives/matter.js';
export { Verfer } from './primitives/verfer.js';
export { Diger } from './primitives/diger.js';
export { Signer } from './primitives/signer.js';
export { Siger } from './primitives/siger.js';
export type { SigerCreateOpts } from './primitives/siger.js';
export { Saider } from './primitives/saider.js';
export { Tholder } from './primitives/tholder.js';
export type { TholderOpts } from './primitives/tholder.js';
export { Fraction } from './primitives/fraction.js';
export {
  MtrDex, MtrSizage,
  IdrDex, IdrSizage, IdxSigDex, IdxSigSizage,
  CtrDex, CtrDex_1_0, CtrDex_2_0,
} from './primitives/code-table.js';
export type { Sizage, IndexedSizage, MtrDexCode, IdrDexCode } from './primitives/code-table.js';
export type { CesrDomains } from './primitives/types.js';

// ── Composition ──
export { makeVersionString, parseVersionString } from './composition/version-string.js';
export type { VersionInfo } from './composition/version-string.js';
export { Serder } from './composition/serder.js';
