/**
 * Cloud agent HTTP API contract — defines the endpoints a cloud agent exposes.
 * This is the interface that Signify clients connect to.
 */

export interface BootEndpoint {
  /** Provision a new agent instance for a controller. */
  provision(
    controllerAid: string,
    signature: string,
  ): Promise<{ agentAid: string; endpoints: string[] }>;
}

export interface AdminEndpoint {
  /** Submit a signed event for processing. */
  submitEvent(
    controllerId: string,
    cesr: Uint8Array,
    signature: string,
  ): Promise<{ accepted: boolean; said?: string }>;

  /** Query key state for an AID. */
  queryKeyState(
    controllerId: string,
    targetAid: string,
  ): Promise<Record<string, unknown> | null>;

  /** List managed identifiers. */
  listIdentifiers(
    controllerId: string,
  ): Promise<Array<{ alias: string; prefix: string }>>;
}

export interface EventProcessor {
  /** Process an inbound CESR message through the validation pipeline. */
  process(
    cesr: Uint8Array,
  ): Promise<{ status: 'accepted' | 'escrowed' | 'rejected'; reason?: string }>;

  /** Sweep escrows and promote resolved events. */
  sweepEscrows(): Promise<number>;
}
