export interface AgentConfig {
  readonly controllerId: string;
  readonly agentId: string;
  readonly createdAt: string;
}

export interface CloudAgentPort {
  // Provisioning
  provision(controllerAid: string): Promise<AgentConfig>;
  getAgent(controllerId: string): Promise<AgentConfig | undefined>;
  listAgents(): Promise<AgentConfig[]>;

  // Operations (delegated from controller)
  submitEvent(
    controllerId: string,
    cesr: Uint8Array,
  ): Promise<{ accepted: boolean; said?: string }>;
  queryKeyState(
    controllerId: string,
    targetAid: string,
  ): Promise<Record<string, unknown> | null>;
}
