import { toAID } from "../src/types/AID.js";
import type { AID } from "../src/types/AID.js";
import type { KeyState } from "../src/types/KeyState.js";

/** CESR base64 alphabet */
const B64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Base64url encode raw bytes using the CESR alphabet. */
function encodeB64(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Encode a 32-byte Ed25519 public key as a qb64 Matter with code 'D'.
 * CESR format: 'D' + base64url([0x00, ...keyBytes]) dropping the leading 'A'.
 */
export function encodeEd25519Verfer(keyBytes: Uint8Array): string {
  // paw = [0, ...keyBytes] (ps=1 lead byte for code D with hs=1)
  const paw = new Uint8Array(33);
  paw[0] = 0;
  paw.set(keyBytes, 1);
  const all = encodeB64(paw); // 44 chars; paw[0]=0 → first char is 'A'
  return "D" + all.slice(1); // replace leading 'A' with code 'D'
}

/**
 * Encode a 64-byte Ed25519 signature as a qb64 Indexer with code 'A' + index.
 * CESR format: 'A' + b64(index) + base64url(sigBytes)
 *
 * The Indexer parser for code 'A' (hs=1, ss=1, ls=0, fs=88) does:
 *   raw = decodeB64(qb64.slice(2, 88))
 * So qb64.slice(2) must be the 86-char base64url encoding of the 64-byte sig.
 */
export function encodeEd25519IndexedSig(
  sigBytes: Uint8Array,
  index: number,
): string {
  const indexChar = B64[index];
  const sigB64 = encodeB64(sigBytes); // 64 bytes → 86 chars (base64url, no padding)
  return "A" + indexChar + sigB64; // 1 + 1 + 86 = 88 chars
}

export interface Ed25519KeyPair {
  publicKeyBytes: Uint8Array;
  privateKey: CryptoKey;
  verferQb64: string;
}

/** Generate a fresh Ed25519 key pair and encode the public key as a qb64 verfer. */
export async function generateKeyPair(): Promise<Ed25519KeyPair> {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const rawPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  return {
    publicKeyBytes: rawPublic,
    privateKey: keyPair.privateKey,
    verferQb64: encodeEd25519Verfer(rawPublic),
  };
}

/** Sign a message with an Ed25519 private key, returning raw 64-byte signature. */
export async function signMessage(
  privateKey: CryptoKey,
  message: Uint8Array,
): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, message);
  return new Uint8Array(sig);
}

/**
 * Build a minimal KERI version-1 JSON message (UTF-8 bytes).
 * The "v" field size placeholder is calculated so the total byte length
 * of the JSON matches the hex in the version string.
 */
export function makeKeriJson(
  fields: Record<string, unknown>,
): Uint8Array {
  const placeholder = "KERI10JSON000000_";
  const withPlaceholder = JSON.stringify({ v: placeholder, ...fields });
  const size = withPlaceholder.length;
  const sizeHex = size.toString(16).padStart(6, "0");
  const finalJson = withPlaceholder.replace(
    "KERI10JSON000000_",
    `KERI10JSON${sizeHex}_`,
  );
  return new TextEncoder().encode(finalJson);
}

/** Build a simple KeyState with a single key and threshold "1". */
export function makeKeyState(verferQb64: string, aid?: AID): KeyState {
  return {
    currentKeys: [verferQb64],
    threshold: "1",
    sn: 0n,
    witnessAids: [],
  };
}

/** Make a dummy AID string (not cryptographically valid, for store-only tests). */
export function dummyAID(label: string): AID {
  return toAID(`B${label.padEnd(43, "A")}`);
}
