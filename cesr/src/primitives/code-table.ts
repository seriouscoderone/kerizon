/**
 * CESR Master Code Table — sizage definitions for Matter and Indexed-Signature primitives.
 *
 * Reference: CESR spec section 12 (Master Code Table)
 *
 * hs = hard size   — number of code chars in T-domain
 * ss = soft size   — number of variable index/count chars in T-domain
 * fs = full size   — total T-domain chars (0 = variable length)
 * ls = lead size   — number of leading pad bytes in B-domain
 */

// ---------------------------------------------------------------------------
// Matter (non-indexed) primitives
// ---------------------------------------------------------------------------

/** Sizage entry for a Matter code. */
export interface Sizage {
  readonly hs: number;
  readonly ss: number;
  readonly fs: number;
  readonly ls: number;
}

/**
 * Matter code table — human-readable names mapped to code strings.
 */
export const MtrDex = {
  // 1-character codes (hs=1, ss=0)
  Ed25519_Seed:    'A',
  Ed25519N:        'B',
  X25519:          'C',
  Ed25519:         'D',
  Blake3_256:      'E',
  Blake2b_256:     'F',
  SHA3_256:        'G',
  SHA2_256:        'H',
  ECDSA_256k1N:    'I',
  ECDSA_256k1:     'J',
  Ed448N:          'K',
  Ed448:           'L',
  Short:           'M',
  Big:             'N',

  // 2-character codes (hs=2, ss=0)
  Salt_128:        '0A',
  Ed25519_Sig:     '0B',
  ECDSA_256k1_Sig: '0C',
  SHA3_512:        '0D',
  Blake3_512:      '0E',

  // 4-character codes (hs=4, ss=0)
  ECDSA_256k1_Ver: '1AAA',
  DateTime:        '1AAG',
} as const;

export type MtrDexCode = (typeof MtrDex)[keyof typeof MtrDex];

/**
 * Sizage table for every Matter code.
 *
 * For all fixed-size codes, ls=0 because the raw material size is chosen to
 * exactly fill the value portion of the T-domain representation:
 *   raw_bytes = floor((fs - hs - ss) * 3 / 4)
 */
export const MtrSizage: Record<string, Sizage> = {
  // 1-char codes with 32-byte raw (fs=44)
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

  // 1-char codes with 56-byte raw (fs=76)
  'K': { hs: 1, ss: 0, fs: 76, ls: 0 },
  'L': { hs: 1, ss: 0, fs: 76, ls: 0 },

  // 1-char codes with smaller raw
  'M': { hs: 1, ss: 0, fs:  4, ls: 0 },   // 2-byte raw
  'N': { hs: 1, ss: 0, fs: 12, ls: 0 },   // 8-byte raw

  // 2-char codes with 16-byte raw (fs=24)
  '0A': { hs: 2, ss: 0, fs: 24, ls: 0 },

  // 2-char codes with 64-byte raw (fs=88)
  '0B': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0C': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0D': { hs: 2, ss: 0, fs: 88, ls: 0 },
  '0E': { hs: 2, ss: 0, fs: 88, ls: 0 },

  // 4-char codes with 33-byte raw (fs=48)
  '1AAA': { hs: 4, ss: 0, fs: 48, ls: 0 },

  // 4-char codes with 24-byte raw (fs=36)
  '1AAG': { hs: 4, ss: 0, fs: 36, ls: 0 },
};

// ---------------------------------------------------------------------------
// Indexed-signature primitives
// ---------------------------------------------------------------------------

/** Sizage entry for an Indexed Signature code. */
export interface IndexedSizage {
  readonly hs: number;
  readonly ss: number;
  readonly fs: number;
  readonly ls: number;
  /** ondex size — 0 when ondex equals index, ss when ondex is separate. */
  readonly os: number;
}

/**
 * Indexed Signature code table — human-readable names to code strings.
 */
export const IdxSigDex = {
  Ed25519_Crt:          'A',   // current signer, ondex == index
  ECDSA_256k1_Crt:      'B',   // current signer ECDSA
  Ed448_Crt:            'C',   // current signer Ed448
  Ed25519_Big_Crt:      '2A',  // current signer big index
  ECDSA_256k1_Big_Crt:  '2B',  // current signer big ECDSA

  Ed25519:              '0A',  // both indexes explicit
  ECDSA_256k1:          '0B',  // both indexes explicit ECDSA
  Ed448:                '0C',  // both indexes explicit Ed448
} as const;

export type IdxSigDexCode = (typeof IdxSigDex)[keyof typeof IdxSigDex];

/**
 * Sizage table for Indexed Signature codes.
 */
export const IdxSigSizage: Record<string, IndexedSizage> = {
  // 1-char current-signer codes: hs=1, ss=1, 64-byte sig
  'A': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'B': { hs: 1, ss: 1, fs: 88,  ls: 0, os: 0 },
  'C': { hs: 1, ss: 1, fs: 152, ls: 0, os: 0 },  // Ed448: 114-byte sig

  // 2-char both-index codes: hs=2, ss=2, 64-byte sig
  '0A': { hs: 2, ss: 2, fs: 88,  ls: 0, os: 2 },
  '0B': { hs: 2, ss: 2, fs: 88,  ls: 0, os: 2 },
  '0C': { hs: 2, ss: 2, fs: 152, ls: 0, os: 2 },  // Ed448

  // 2-char big-index current-signer codes: hs=2, ss=2, 64-byte sig
  '2A': { hs: 2, ss: 2, fs: 92,  ls: 0, os: 0 },
  '2B': { hs: 2, ss: 2, fs: 92,  ls: 0, os: 0 },
};
