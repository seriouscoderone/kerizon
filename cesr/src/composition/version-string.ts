/**
 * VersionString — KERI v1 version string encoding and decoding.
 *
 * Format: PPPPvvKKKKllllll_ (17 chars, underscore terminated)
 *   PPPP    = protocol identifier (4 chars, e.g. "KERI")
 *   vv      = major + minor as hex digits (e.g. "10" = v1.0)
 *   KKKK    = serialization kind (4 chars, e.g. "JSON")
 *   llllll  = serialized size in hex (6 chars, zero-padded)
 *   _       = terminator
 */

const VS_LENGTH = 17;
const TERMINATOR = '_';

export interface VersionInfo {
  protocol: string;  // 4 chars
  major: number;
  minor: number;
  kind: string;      // JSON, CBOR, MGPK, CESR
  size: number;
}

/**
 * Build a KERI v1 version string from the given info.
 */
export function makeVersionString(info: VersionInfo): string {
  const proto = info.protocol.padEnd(4, ' ').slice(0, 4);
  const ver = info.major.toString(16) + info.minor.toString(16);
  const kind = info.kind.padEnd(4, ' ').slice(0, 4);
  const size = info.size.toString(16).padStart(6, '0');
  return `${proto}${ver}${kind}${size}${TERMINATOR}`;
}

/**
 * Parse a KERI v1 version string back into its components.
 */
export function parseVersionString(vs: string): VersionInfo {
  if (vs.length !== VS_LENGTH) {
    throw new Error(
      `Invalid version string length: expected ${VS_LENGTH}, got ${vs.length}`,
    );
  }
  if (vs[VS_LENGTH - 1] !== TERMINATOR) {
    throw new Error(
      `Invalid version string terminator: expected '${TERMINATOR}', got '${vs[VS_LENGTH - 1]}'`,
    );
  }

  const protocol = vs.slice(0, 4);
  const major = parseInt(vs[4], 16);
  const minor = parseInt(vs[5], 16);
  const kind = vs.slice(6, 10);
  const size = parseInt(vs.slice(10, 16), 16);

  return { protocol, major, minor, kind, size };
}
