/** An opaque message payload with its content-addressable digest. */
export interface Envelope {
  payload: Uint8Array;
  digest: string;
}
