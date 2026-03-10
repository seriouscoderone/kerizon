/**
 * Construct a database key from (prefix, digest).
 * Identifies a specific event version.
 */
export function digestKey(prefix: string, digest: string): string {
  return `${prefix}:${digest}`;
}

/**
 * Construct a database key from (prefix, sequenceNumber).
 * Identifies events at a given sequence number.
 */
export function sequenceKey(prefix: string, sequenceNumber: number): string {
  return `${prefix}:${sequenceNumber}`;
}
