/**
 * Cryptographic hash functions for SAID verification.
 * Uses @noble/hashes for pure-JS implementations.
 */

import { blake3 } from '@noble/hashes/blake3';
import { blake2b } from '@noble/hashes/blake2b';
import { sha256 } from '@noble/hashes/sha2';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3';

export type HashAlgo = 'blake3-256' | 'blake2b-256' | 'sha3-256' | 'sha2-256' | 'sha3-512';

/** Compute a digest using the specified algorithm. */
export function digest(data: Uint8Array, algo: HashAlgo): Uint8Array {
  switch (algo) {
    case 'blake3-256':
      return blake3(data, { dkLen: 32 });
    case 'blake2b-256':
      return blake2b(data, { dkLen: 32 });
    case 'sha3-256':
      return sha3_256(data);
    case 'sha2-256':
      return sha256(data);
    case 'sha3-512':
      return sha3_512(data);
  }
}

/** Map CESR derivation codes to hash algorithms and output sizes. */
export const DIGEST_CODES: Record<string, { algo: HashAlgo; rawSize: number }> = {
  'E': { algo: 'blake3-256', rawSize: 32 },
  'F': { algo: 'blake2b-256', rawSize: 32 },
  'G': { algo: 'sha3-256', rawSize: 32 },
  'H': { algo: 'sha2-256', rawSize: 32 },
  '0D': { algo: 'sha3-512', rawSize: 64 },
};
