import { describe, it, expect } from 'vitest';
import { LocalAgent } from '../../src/local-agent/agent.js';
import { CredentialLifecycle } from '../../src/credential-lifecycle/facade.js';
import { CredentialExchange } from '../../src/credential-exchange/orchestrator.js';
import { WatcherService } from '../../src/watcher-service/orchestrator.js';

describe('LocalAgent', () => {
  function createAgent() {
    return new LocalAgent({
      credentials: new CredentialLifecycle(),
      exchange: new CredentialExchange(),
      watcher: new WatcherService(),
    });
  }

  it('constructs with all components', () => {
    const agent = createAgent();
    expect(agent).toBeDefined();
  });

  it('exposes credentials, exchange, and watcher', () => {
    const agent = createAgent();
    expect(agent.credentials).toBeInstanceOf(CredentialLifecycle);
    expect(agent.exchange).toBeInstanceOf(CredentialExchange);
    expect(agent.watcher).toBeInstanceOf(WatcherService);
  });

  it('identity.list starts empty', () => {
    const agent = createAgent();
    expect(agent.identity.list()).toEqual([]);
  });
});
