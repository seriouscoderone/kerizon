/**
 * Transport port interfaces for the witness service.
 * These are the "externals" that concrete adapters implement.
 * The witness domain logic depends only on these interfaces.
 */

/** Handler that the witness exposes to transport adapters. */
export interface WitnessHandler {
  /** Process a submitted CESR event. */
  handleEventSubmission(cesr: Uint8Array): Promise<{ status: number; body?: string }>;

  /** Serve an OOBI request. Returns CESR response with headers. */
  handleOobiRequest(path: string): Promise<{
    status: number;
    contentType: string;
    headers: Record<string, string>;
    body: string;
  }>;

  /** Query KEL for a prefix. */
  handleKelQuery(prefix: string): Promise<{ status: number; body?: string }>;
}

/** Transport server interface — implemented by platform-specific adapters. */
export interface TransportServer {
  listen(port: number): Promise<void>;
  stop(): Promise<void>;
}

/**
 * Factory function type for creating a transport server from a handler.
 * This is what platform adapters export.
 */
export type CreateTransportServer = (handler: WitnessHandler) => TransportServer;
