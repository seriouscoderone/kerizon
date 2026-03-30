import { describe, it, expect } from 'vitest';
import type {
  BootEndpoint,
  AdminEndpoint,
  EventProcessor,
} from '../../src/cloud-agent/api.js';

describe('BootEndpoint', () => {
  it('interface can be implemented with provision method', () => {
    const boot: BootEndpoint = {
      provision: async () => ({
        agentAid: 'EAgent123',
        endpoints: ['http://localhost:3901'],
      }),
    };

    expect(boot.provision).toBeDefined();
    expect(typeof boot.provision).toBe('function');
  });
});

describe('AdminEndpoint', () => {
  it('has submitEvent, queryKeyState, and listIdentifiers', () => {
    const admin: AdminEndpoint = {
      submitEvent: async () => ({ accepted: true, said: 'ESAID' }),
      queryKeyState: async () => null,
      listIdentifiers: async () => [],
    };

    expect(admin.submitEvent).toBeDefined();
    expect(admin.queryKeyState).toBeDefined();
    expect(admin.listIdentifiers).toBeDefined();
  });
});

describe('EventProcessor', () => {
  it('has process and sweepEscrows methods', () => {
    const processor: EventProcessor = {
      process: async () => ({ status: 'accepted' }),
      sweepEscrows: async () => 0,
    };

    expect(processor.process).toBeDefined();
    expect(processor.sweepEscrows).toBeDefined();
    expect(typeof processor.process).toBe('function');
    expect(typeof processor.sweepEscrows).toBe('function');
  });
});
