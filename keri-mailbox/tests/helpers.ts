import { Matter, Indexer } from "cesr-codec";
import { toAID } from "../src/types/AID.js";
import type { AID } from "../src/types/AID.js";
import type { KeyState } from "../src/types/KeyState.js";

/**
 * Encode a 32-byte Ed25519 public key as a qb64 Matter with code 'D'.
 */
export function encodeEd25519Verfer(keyBytes: Uint8Array): string {
  return new Matter({ code: "D", raw: keyBytes }).qb64;
}

/**
 * Encode a 64-byte Ed25519 signature as a qb64 Indexer with code 'A' + index.
 */
export function encodeEd25519IndexedSig(
  sigBytes: Uint8Array,
  index: number,
): string {
  return new Indexer({ code: "A", raw: sigBytes, index }).qb64;
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
  const sig = await crypto.subtle.sign("Ed25519", privateKey, message.slice());
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
