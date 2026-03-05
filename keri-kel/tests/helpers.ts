import { encodeB64, intToB64 } from "cesr-ts";

/**
 * Encode a 32-byte Ed25519 public key as a qb64 Matter with code 'D'.
 * CESR format: 'D' + base64url([0x00, ...keyBytes]) dropping the leading 'A'.
 */
export function encodeEd25519Verfer(keyBytes: Uint8Array): string {
  const paw = new Uint8Array(33);
  paw[0] = 0;
  paw.set(keyBytes, 1);
  const all = encodeB64(paw);
  return "D" + all.slice(1);
}

/**
 * Encode a 64-byte Ed25519 signature as a qb64 Indexer with code 'A' + index.
 * CESR format: 'A' + b64(index) + base64url(sigBytes)
 */
export function encodeEd25519IndexedSig(
  sigBytes: Uint8Array,
  index: number,
): string {
  const indexChar = intToB64(index, 1);
  const sigB64 = encodeB64(sigBytes);
  return "A" + indexChar + sigB64;
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

/**
 * Build a KERI JSON event with version string and compute SAID placeholders.
 * Returns the event fields object with correct version string size.
 */
export function buildKeriEvent(
  fields: Record<string, unknown>,
): Record<string, unknown> {
  const bytes = makeKeriJson(fields);
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json) as Record<string, unknown>;
}
