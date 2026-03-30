import { describe, it, expect } from 'vitest';
import type {
  SignifyResources,
  IdentifierResource,
  CredentialResource,
} from '../../src/signify-client/resources.js';

describe('SignifyResources', () => {
  it('has all resource properties', () => {
    const resources: SignifyResources = {
      identifiers: {
        list: async () => [],
        get: async () => ({ prefix: 'EPrefix', sn: 0, keys: [] }),
        create: async () => ({ prefix: 'EPrefix' }),
        rotate: async () => ({ sn: 1 }),
        interact: async () => ({ sn: 2 }),
      },
      credentials: {
        list: async () => [],
        get: async () => ({}),
        issue: async () => ({ said: 'ESAID' }),
        revoke: async () => {},
      },
      registries: {
        list: async () => [],
        create: async () => ({ regid: 'ERegId' }),
      },
      exchanges: {
        send: async () => ({ said: 'ESAID' }),
        list: async () => [],
      },
      oobis: {
        resolve: async () => ({ aid: 'EAid', endpoints: [] }),
        generate: async () => [],
      },
    };

    expect(resources.identifiers).toBeDefined();
    expect(resources.credentials).toBeDefined();
    expect(resources.registries).toBeDefined();
    expect(resources.exchanges).toBeDefined();
    expect(resources.oobis).toBeDefined();
  });
});

describe('IdentifierResource', () => {
  it('has CRUD methods: list, get, create, rotate, interact', () => {
    const ids: IdentifierResource = {
      list: async () => [],
      get: async () => ({ prefix: 'EPrefix', sn: 0, keys: ['DKey1'] }),
      create: async () => ({ prefix: 'ENewPrefix' }),
      rotate: async () => ({ sn: 1 }),
      interact: async () => ({ sn: 2 }),
    };

    expect(ids.list).toBeDefined();
    expect(ids.get).toBeDefined();
    expect(ids.create).toBeDefined();
    expect(ids.rotate).toBeDefined();
    expect(ids.interact).toBeDefined();
  });
});

describe('CredentialResource', () => {
  it('has issue and revoke methods', () => {
    const creds: CredentialResource = {
      list: async () => [],
      get: async () => ({}),
      issue: async () => ({ said: 'ESAID' }),
      revoke: async () => {},
    };

    expect(creds.issue).toBeDefined();
    expect(creds.revoke).toBeDefined();
    expect(typeof creds.issue).toBe('function');
    expect(typeof creds.revoke).toBe('function');
  });
});
