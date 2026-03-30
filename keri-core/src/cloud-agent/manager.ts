import type { AgentConfig } from './types.js';

export class AgentManager {
  private agents = new Map<string, AgentConfig>();

  provision(controllerAid: string, agentAid: string): AgentConfig {
    const existing = this.agents.get(controllerAid);
    if (existing) return existing;

    const config: AgentConfig = {
      controllerId: controllerAid,
      agentId: agentAid,
      createdAt: new Date().toISOString(),
    };
    this.agents.set(controllerAid, config);
    return config;
  }

  getAgent(controllerId: string): AgentConfig | undefined {
    return this.agents.get(controllerId);
  }

  listAgents(): AgentConfig[] {
    return [...this.agents.values()];
  }
}
