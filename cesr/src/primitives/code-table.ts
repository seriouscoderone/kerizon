/**
 * CESR Master Code Table — complete sizage definitions for Matter, Indexer,
 * and Counter primitives.
 *
 * Extracted from keripy 1.3.4: keri.core.coring.Matter.Sizes,
 * keri.core.indexing.Indexer.Sizes, keri.core.counting.CtrDex_1_0/2_0.
 *
 * hs = hard size   — number of code chars in T-domain
 * ss = soft size   — number of variable index/count chars in T-domain
 * fs = full size   — total T-domain chars (0 = variable length)
 * ls = lead size   — number of leading pad bytes in B-domain
 * os = other index size (Indexer only)
 */

// ═══════════════════════════════════════════════════════════════════════════
// Matter (non-indexed) primitives — 107 entries
// ═══════════════════════════════════════════════════════════════════════════

export interface Sizage {
  readonly hs: number;
  readonly ss: number;
  readonly fs: number;  // 0 = variable length (actual size encoded in soft chars)
  readonly ls: number;
}

export const MtrDex = {
  // ── 1-char codes (A–Z) ──
  Ed25519_Seed:       'A',
  Ed25519N:           'B',
  X25519:             'C',
  Ed25519:            'D',
  Blake3_256:         'E',
  Blake2b_256:        'F',
  Blake2s_256:        'G',
  SHA3_256:           'H',
  SHA2_256:           'I',
  ECDSA_256k1_Seed:   'J',
  Ed448_Seed:         'K',
  X448:               'L',
  Short:              'M',
  Big:                'N',
  X25519_Private:     'O',
  X25519_Cipher_Seed: 'P',
  ECDSA_256r1_Seed:   'Q',
  Tall:               'R',
  Large:              'S',
  Great:              'T',
  Vast:               'U',
  Label1:             'V',
  Label2:             'W',
  Tag3:               'X',
  Tag7:               'Y',
  Blind:              'Z',

  // ── 2-char codes (0A–0S) ──
  Salt_128:           '0A',
  Ed25519_Sig:        '0B',
  ECDSA_256k1_Sig:    '0C',
  Blake3_512:         '0D',
  Blake2b_512:        '0E',
  SHA3_512:           '0F',
  SHA2_512:           '0G',
  Long:               '0H',
  ECDSA_256r1_Sig:    '0I',
  Tag1:               '0J',
  Tag2:               '0K',
  Tag5:               '0L',
  Tag6:               '0M',
  Tag9:               '0N',
  Tag10:              '0O',
  GramHeadNeck:       '0P',
  GramHead:           '0Q',
  GramHeadAIDNeck:    '0R',
  GramHeadAID:        '0S',

  // ── 2-char variable-length codes (4A–6G) ──
  StrB64_L0:                '4A',
  Bytes_L0:                 '4B',
  X25519_Cipher_L0:         '4C',
  X25519_Cipher_QB64_L0:    '4D',
  X25519_Cipher_QB2_L0:     '4E',
  HPKEBase_Cipher_L0:       '4F',
  HPKEAuth_Cipher_L0:       '4G',
  StrB64_L1:                '5A',
  Bytes_L1:                 '5B',
  X25519_Cipher_L1:         '5C',
  X25519_Cipher_QB64_L1:    '5D',
  X25519_Cipher_QB2_L1:     '5E',
  HPKEBase_Cipher_L1:       '5F',
  HPKEAuth_Cipher_L1:       '5G',
  StrB64_L2:                '6A',
  Bytes_L2:                 '6B',
  X25519_Cipher_L2:         '6C',
  X25519_Cipher_QB64_L2:    '6D',
  X25519_Cipher_QB2_L2:     '6E',
  HPKEBase_Cipher_L2:       '6F',
  HPKEAuth_Cipher_L2:       '6G',

  // ── 4-char codes (1AAA–1AAN) ──
  ECDSA_256k1N:       '1AAA',
  ECDSA_256k1:        '1AAB',
  Ed448N:             '1AAC',
  Ed448:              '1AAD',
  Ed448_Sig:          '1AAE',
  Tag4:               '1AAF',
  DateTime:           '1AAG',
  X25519_Cipher_Salt: '1AAH',
  ECDSA_256r1N:       '1AAI',
  ECDSA_256r1:        '1AAJ',
  Null:               '1AAK',
  No:                 '1AAL',
  Yes:                '1AAM',
  Tag8:               '1AAN',

  // ── 4-char TBD codes ──
  TBD0S:  '1__-',
  TBD0:   '1___',
  TBD1S:  '2__-',
  TBD1:   '2___',
  TBD2S:  '3__-',
  TBD2:   '3___',

  // ── 4-char variable-length big codes (7AAA–9AAG) ──
  StrB64_Big_L0:              '7AAA',
  Bytes_Big_L0:               '7AAB',
  X25519_Cipher_Big_L0:       '7AAC',
  X25519_Cipher_QB64_Big_L0:  '7AAD',
  X25519_Cipher_QB2_Big_L0:   '7AAE',
  HPKEBase_Cipher_Big_L0:     '7AAF',
  HPKEAuth_Cipher_Big_L0:     '7AAG',
  StrB64_Big_L1:              '8AAA',
  Bytes_Big_L1:               '8AAB',
  X25519_Cipher_Big_L1:       '8AAC',
  X25519_Cipher_QB64_Big_L1:  '8AAD',
  X25519_Cipher_QB2_Big_L1:   '8AAE',
  HPKEBase_Cipher_Big_L1:     '8AAF',
  HPKEAuth_Cipher_Big_L1:     '8AAG',
  StrB64_Big_L2:              '9AAA',
  Bytes_Big_L2:               '9AAB',
  X25519_Cipher_Big_L2:       '9AAC',
  X25519_Cipher_QB64_Big_L2:  '9AAD',
  X25519_Cipher_QB2_Big_L2:   '9AAE',
  HPKEBase_Cipher_Big_L2:     '9AAF',
  HPKEAuth_Cipher_Big_L2:     '9AAG',
} as const;

export type MtrDexCode = (typeof MtrDex)[keyof typeof MtrDex];

/**
 * Sizage for every Matter code.
 * fs=0 indicates variable-length (size encoded in soft chars).
 */
export const MtrSizage: Record<string, Sizage> = {
  // 1-char, 32-byte raw (fs=44)
  'A': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'B': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'C': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'D': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'E': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'F': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'G': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'H': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'I': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'J': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'O': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'Q': { hs: 1, ss: 0, fs: 44, ls: 0 },
  'Z': { hs: 1, ss: 0, fs: 44, ls: 0 },

  // 1-char, 56-byte raw (fs=76)
  'K': { hs: 1, ss: 0, fs: 76, ls: 0 },
  'L': { hs: 1, ss: 0, fs: 76, ls: 0 },

  // 1-char, smaller raw
  'M': { hs: 1, ss: 0, fs: 4,   ls: 0 },   // 2-byte
  'N': { hs: 1, ss: 0, fs: 12,  ls: 0 },   // 8-byte
  'P': { hs: 1, ss: 0, fs: 124, ls: 0 },   // 92-byte (X25519 cipher seed)
  'R': { hs: 1, ss: 0, fs: 8,   ls: 0 },   // 5-byte
  'S': { hs: 1, ss: 0, fs: 16,  ls: 0 },   // 11-byte
  'T': { hs: 1, ss: 0, fs: 20,  ls: 0 },   // 14-byte
  'U': { hs: 1, ss: 0, fs: 24,  ls: 0 },   // 17-byte

  // 1-char labels/tags (with soft or lead sizes)
  'V': { hs: 1, ss: 0, fs: 4, ls: 1 },
  'W': { hs: 1, ss: 0, fs: 4, ls: 0 },
  'X': { hs: 1, ss: 3, fs: 4, ls: 0 },
  'Y': { hs: 1, ss: 7, fs: 8, ls: 0 },

  // 2-char, 16-byte raw (fs=24)
  '0A': { hs: 2, ss: 0, fs: 24, ls: 0 },

  // 2-char, 64-byte raw (fs=88)
  '0B': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0C': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0D': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0E': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0F': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0G': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0I': { hs: 2, ss: 0, fs: 88, ls: 0 },

  // 2-char, smaller fixed
  '0H': { hs: 2, ss: 0, fs: 8,  ls: 0 },  // Long: 4-byte

  // 2-char tags (with soft sizes)
  '0J': { hs: 2, ss: 2,  fs: 4,  ls: 0 },
  '0K': { hs: 2, ss: 2,  fs: 4,  ls: 0 },
  '0L': { hs: 2, ss: 6,  fs: 8,  ls: 0 },
  '0M': { hs: 2, ss: 6,  fs: 8,  ls: 0 },
  '0N': { hs: 2, ss: 10, fs: 12, ls: 0 },
  '0O': { hs: 2, ss: 10, fs: 12, ls: 0 },

  // 2-char grammar codes
  '0P': { hs: 2, ss: 22, fs: 32, ls: 0 },
  '0Q': { hs: 2, ss: 22, fs: 28, ls: 0 },
  '0R': { hs: 2, ss: 22, fs: 76, ls: 0 },
  '0S': { hs: 2, ss: 22, fs: 72, ls: 0 },

  // 2-char variable-length (fs=0)
  '4A': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4B': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4C': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4D': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4E': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4F': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '4G': { hs: 2, ss: 2, fs: 0, ls: 0 },
  '5A': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5B': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5C': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5D': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5E': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5F': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '5G': { hs: 2, ss: 2, fs: 0, ls: 1 },
  '6A': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6B': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6C': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6D': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6E': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6F': { hs: 2, ss: 2, fs: 0, ls: 2 },
  '6G': { hs: 2, ss: 2, fs: 0, ls: 2 },

  // 4-char fixed
  '1AAA': { hs: 4, ss: 0, fs: 48,  ls: 0 },
  '1AAB': { hs: 4, ss: 0, fs: 48,  ls: 0 },
  '1AAC': { hs: 4, ss: 0, fs: 80,  ls: 0 },
  '1AAD': { hs: 4, ss: 0, fs: 80,  ls: 0 },
  '1AAE': { hs: 4, ss: 0, fs: 156, ls: 0 },
  '1AAF': { hs: 4, ss: 4, fs: 8,   ls: 0 },
  '1AAG': { hs: 4, ss: 0, fs: 36,  ls: 0 },
  '1AAH': { hs: 4, ss: 0, fs: 100, ls: 0 },
  '1AAI': { hs: 4, ss: 0, fs: 48,  ls: 0 },
  '1AAJ': { hs: 4, ss: 0, fs: 48,  ls: 0 },
  '1AAK': { hs: 4, ss: 0, fs: 4,   ls: 0 },
  '1AAL': { hs: 4, ss: 0, fs: 4,   ls: 0 },
  '1AAM': { hs: 4, ss: 0, fs: 4,   ls: 0 },
  '1AAN': { hs: 4, ss: 8, fs: 12,  ls: 0 },

  // 4-char TBD
  '1__-': { hs: 4, ss: 2, fs: 12, ls: 0 },
  '1___': { hs: 4, ss: 0, fs: 8,  ls: 0 },
  '2__-': { hs: 4, ss: 2, fs: 12, ls: 1 },
  '2___': { hs: 4, ss: 0, fs: 8,  ls: 1 },
  '3__-': { hs: 4, ss: 2, fs: 12, ls: 2 },
  '3___': { hs: 4, ss: 0, fs: 8,  ls: 2 },

  // 4-char variable-length big (fs=0)
  '7AAA': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAB': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAC': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAD': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAE': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAF': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '7AAG': { hs: 4, ss: 4, fs: 0, ls: 0 },
  '8AAA': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAB': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAC': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAD': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAE': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAF': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '8AAG': { hs: 4, ss: 4, fs: 0, ls: 1 },
  '9AAA': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAB': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAC': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAD': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAE': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAF': { hs: 4, ss: 4, fs: 0, ls: 2 },
  '9AAG': { hs: 4, ss: 4, fs: 0, ls: 2 },
};

// ═══════════════════════════════════════════════════════════════════════════
// Indexed-signature primitives — 19 entries
// ═══════════════════════════════════════════════════════════════════════════

export interface IndexedSizage {
  readonly hs: number;
  readonly ss: number;
  readonly fs: number;  // 0 = variable length
  readonly ls: number;
  readonly os: number;  // other index size (0 = ondex == index)
}

export const IdrDex = {
  // 1-char current-signer (ondex == index)
  Ed25519_Sig:          'A',
  Ed25519_Crt_Sig:      'B',
  ECDSA_256k1_Sig:      'C',
  ECDSA_256k1_Crt_Sig:  'D',
  ECDSA_256r1_Sig:      'E',
  ECDSA_256r1_Crt_Sig:  'F',

  // 2-char both-index explicit
  Ed448_Sig:            '0A',
  Ed448_Crt_Sig:        '0B',

  // 2-char big-index current-signer
  Ed25519_Big_Sig:          '2A',
  Ed25519_Big_Crt_Sig:      '2B',
  ECDSA_256k1_Big_Sig:      '2C',
  ECDSA_256k1_Big_Crt_Sig:  '2D',
  ECDSA_256r1_Big_Sig:      '2E',
  ECDSA_256r1_Big_Crt_Sig:  '2F',

  // 2-char big-index both-index
  Ed448_Big_Sig:          '3A',
  Ed448_Big_Crt_Sig:      '3B',

  // TBD
  TBD0: '0z',
  TBD1: '1z',
  TBD4: '4z',
} as const;

/** Backwards-compatible alias */
export const IdxSigDex = IdrDex;

export type IdrDexCode = (typeof IdrDex)[keyof typeof IdrDex];

export const IdrSizage: Record<string, IndexedSizage> = {
  // 1-char, Ed25519 64-byte sig
  'A': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'B': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  // 1-char, ECDSA 64-byte sig
  'C': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'D': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'E': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'F': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },

  // 2-char, Ed448 114-byte sig, both indexes
  '0A': { hs: 2, ss: 2, fs: 156, ls: 0, os: 1 },
  '0B': { hs: 2, ss: 2, fs: 156, ls: 0, os: 1 },

  // 2-char big index, Ed25519 64-byte sig
  '2A': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },
  '2B': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },
  // 2-char big index, ECDSA 64-byte sig
  '2C': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },
  '2D': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },
  '2E': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },
  '2F': { hs: 2, ss: 4, fs: 92,  ls: 0, os: 2 },

  // 2-char big index, Ed448 114-byte sig
  '3A': { hs: 2, ss: 6, fs: 160, ls: 0, os: 3 },
  '3B': { hs: 2, ss: 6, fs: 160, ls: 0, os: 3 },

  // TBD
  '0z': { hs: 2, ss: 2, fs: 0,  ls: 0, os: 0 },
  '1z': { hs: 2, ss: 2, fs: 76, ls: 1, os: 1 },
  '4z': { hs: 2, ss: 6, fs: 80, ls: 1, os: 3 },
};

/** Backwards-compatible alias */
export const IdxSigSizage = IdrSizage;

// ═══════════════════════════════════════════════════════════════════════════
// Counter codes — v1.0 (20 entries) and v2.0 (48 entries)
// ═══════════════════════════════════════════════════════════════════════════

export const CtrDex_1_0 = {
  ControllerIdxSigs:      '-A',
  WitnessIdxSigs:         '-B',
  NonTransReceiptCouples:  '-C',
  TransReceiptQuadruples:  '-D',
  FirstSeenReplayCouples:  '-E',
  TransIdxSigGroups:       '-F',
  SealSourceCouples:       '-G',
  TransLastIdxSigGroups:   '-H',
  SealSourceTriples:       '-I',
  SadPathSigGroups:        '-J',
  RootSadPathSigGroups:    '-K',
  PathedMaterialGroup:     '-L',
  AttachmentGroup:         '-V',
  GenericGroup:            '-W',
  ESSRPayloadGroup:        '-Z',
  BigAttachmentGroup:      '-0V',
  BigGenericGroup:         '-0W',
  BigESSRPayloadGroup:     '-0Z',
  BigPathedMaterialGroup:  '-0L',
  KERIACDCGenusVersion:    '--AAA',
} as const;

export const CtrDex_2_0 = {
  GenericGroup:             '-A',
  MessageGroup:             '-B',
  AttachmentGroup:          '-C',
  DatagramSegmentGroup:     '-D',
  ESSRWrapperGroup:         '-E',
  FixedMessageBodyGroup:    '-F',
  MapMessageBodyGroup:      '-G',
  GenericMapGroup:          '-H',
  GenericListGroup:         '-I',
  ControllerIdxSigs:        '-J',
  WitnessIdxSigs:           '-K',
  NonTransReceiptCouples:   '-L',
  TransReceiptQuadruples:   '-M',
  FirstSeenReplayCouples:   '-N',
  TransIdxSigGroups:        '-O',
  TransLastIdxSigGroups:    '-P',
  SealSourceCouples:        '-Q',
  SealSourceTriples:        '-R',
  PathedMaterialGroup:      '-S',
  SadPathSigGroups:         '-T',
  RootSadPathSigGroups:     '-U',
  DigestSealSingles:        '-V',
  MerkleRootSealSingles:    '-W',
  BackerRegistrarSealCouples: '-X',
  SealSourceLastSingles:    '-Y',
  ESSRPayloadGroup:         '-Z',

  BigGenericGroup:              '-0A',
  BigMessageGroup:              '-0B',
  BigAttachmentGroup:           '-0C',
  BigDatagramSegmentGroup:      '-0D',
  BigESSRWrapperGroup:          '-0E',
  BigFixedMessageBodyGroup:     '-0F',
  BigMapMessageBodyGroup:       '-0G',
  BigGenericMapGroup:           '-0H',
  BigGenericListGroup:          '-0I',
  BigControllerIdxSigs:         '-0J',
  BigWitnessIdxSigs:            '-0K',
  BigNonTransReceiptCouples:    '-0L',
  BigTransReceiptQuadruples:    '-0M',
  BigFirstSeenReplayCouples:    '-0N',
  BigTransIdxSigGroups:         '-0O',
  BigTransLastIdxSigGroups:     '-0P',
  BigSealSourceCouples:         '-0Q',
  BigSealSourceTriples:         '-0R',
  BigPathedMaterialGroup:       '-0S',
  BigSadPathSigGroups:          '-0T',
  BigRootSadPathSigGroups:      '-0U',
  BigDigestSealSingles:         '-0V',
  BigMerkleRootSealSingles:     '-0W',
  BigBackerRegistrarSealCouples: '-0X',
  BigSealSourceLastSingles:     '-0Y',
  BigESSRPayloadGroup:          '-0Z',

  KERIACDCGenusVersion:         '--AAA',
} as const;

/** Default counter code table (v1.0 for keripy 1.x compatibility). */
export const CtrDex = CtrDex_1_0;
