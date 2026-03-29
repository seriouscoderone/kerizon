/**
 * @kerizon/cesr — Composable Event Streaming Representation primitives.
 */

export { Matter, encodeB64, decodeB64, b64Index, b64Value, resolveCode, rawSizeFromSizage } from './primitives/matter.js';
export type { MatterArgs } from './primitives/matter.js';
export { MtrDex, MtrSizage, IdxSigDex, IdxSigSizage } from './primitives/code-table.js';
export type { Sizage, IndexedSizage, MtrDexCode, IdxSigDexCode } from './primitives/code-table.js';
export type { CesrDomains } from './primitives/types.js';
