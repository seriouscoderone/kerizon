// Re-export generated low-level codec
export {
  type CodeEntry,
  type CounterEntry,
  type ParseResult,
  CODE_TABLE,
  COUNTER_TABLE,
  CODE_LOOKUP,
  padSize,
  textSize,
  binarySize,
  counterTextSize,
  counterBinarySize,
  selectorDispatch,
  leadConstrainedBits,
  base64urlEncode,
  base64urlDecode,
  TFromR,
  BFromR,
  RFromT,
  RFromB,
} from './codec.js';

// Matter class and helpers
export { Matter, parseMatterFromText } from './matter.js';

// Indexer class and helpers
export { Indexer, parseIndexerFromText, type IndexedCodeEntry, INDEXED_CODE_TABLE } from './indexer.js';

// Counter class and helpers
export { Counter, parseCounterFromText } from './counter.js';

// Stream parser
export {
  parseBytes,
  isPrimitiveTuple,
  type Primitive,
  type CesrBody,
  type CesrFrame,
  type AttachmentGroup,
  type ParseEmission,
} from './parser.js';
