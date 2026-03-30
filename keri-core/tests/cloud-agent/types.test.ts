import { describe, it, expect } from 'vitest';
import type { AgentConfig, CloudAgentPort } from '../../src/cloud-agent/types.js';
import { AgentManager } from '../../src/cloud-agent/manager.js';

describe('AgentConfig', () => {
  it('holds controller and agent identifiers', () => {
    const config: AgentConfig = {
      controllerId: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      agentId: 'EAgentAid____________________________________',
      createdAt: '2026-03-29T00:00:00.000Z',
    };

    expect(config.controllerId).toBeDefined();
    expect(config.agentId).toBeDefined();
    expect(config.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}/);
  });
});

describe('CloudAgentPort', () => {
  it('can be implemented as a mock', () => {
    const mock: CloudAgentPort = {
      provision: async () => ({
        controllerId: 'ECtrl',
        agentId: 'EAgent',
        createdAt: new Date().toISOString(),
      }),
      getAgent: async () => undefined,
      listAgents: async () => [],
      submitEvent: async () => ({ accepted: true, said: 'ESAID' }),
      queryKeyState: async () => null,
    };

    expect(mock.provision).toBeDefined();
    expect(mock.getAgent).toBeDefined();
    expect(mock.listAgents).toBeDefined();
    expect(mock.submitEvent).toBeDefined();
    expect(mock.queryKeyState).toBeDefined();
  });
});

describe('AgentManager', () => {
  it('provision creates an agent', () => {
    const mgr = new AgentManager();
    const config = mgr.provision('ECtrl_1', 'EAgent_1');

    expect(config.controllerId).toBe('ECtrl_1');
    expect(config.agentId).toBe('EAgent_1');
    expect(config.createdAt).toBeDefined();
  });

  it('getAgent returns config by controllerId', () => {
    const mgr = new AgentManager();
    mgr.provision('ECtrl_2', 'EAgent_2');

    const found = mgr.getAgent('ECtrl_2');
    expect(found).toBeDefined();
    expect(found!.agentId).toBe('EAgent_2');
  });

  it('listAgents returns all provisioned agents', () => {
    const mgr = new AgentManager();
    mgr.provision('ECtrl_A', 'EAgent_A');
    mgr.provision('ECtrl_B', 'EAgent_B');

    const agents = mgr.listAgents();
    expect(agents).toHaveLength(2);
  });

  it('provision same controller twice returns existing agent', () => {
    const mgr = new AgentManager();
    const first = mgr.provision('ECtrl_X', 'EAgent_X');
    const second = mgr.provision('ECtrl_X', 'EAgent_Y');

    expect(second).toEqual(first);
    expect(second.agentId).toBe('EAgent_X');
    expect(mgr.listAgents()).toHaveLength(1);
  });

  it('getAgent returns undefined for unknown controller', () => {
    const mgr = new AgentManager();
    expect(mgr.getAgent('ENonExistent')).toBeUndefined();
  });
});
