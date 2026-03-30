import { describe, it, expect } from 'vitest';
import type { LocalAgentPort } from '../../src/local-agent/types.js';

describe('LocalAgentPort', () => {
  it('can be implemented as a mock', () => {
    const mock: LocalAgentPort = {
      createIdentifier: async () => ({ prefix: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc' }),
      rotateKeys: async () => ({ sn: 1 }),
      createInteraction: async () => ({ sn: 2 }),
      getKeyState: async () => ({
        prefix: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
        sn: 0,
        keys: ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'],
        transferable: true,
      }),
      exportKel: async () => new Uint8Array(0),
      importKel: async () => {},
      sign: async () => ['sig1'],
      verify: async () => true,
      createRegistry: async () => 'ERegistry_SAID______________________________',
      issueCredential: async () => 'ECredential_SAID____________________________',
      listCredentials: async () => [{ said: 'ECredSAID___________________________________', state: 'issued' }],
    };

    expect(mock.createIdentifier).toBeDefined();
    expect(mock.rotateKeys).toBeDefined();
    expect(mock.createInteraction).toBeDefined();
    expect(mock.getKeyState).toBeDefined();
    expect(mock.exportKel).toBeDefined();
    expect(mock.importKel).toBeDefined();
    expect(mock.sign).toBeDefined();
    expect(mock.verify).toBeDefined();
    expect(mock.createRegistry).toBeDefined();
    expect(mock.issueCredential).toBeDefined();
    expect(mock.listCredentials).toBeDefined();
  });

  it('defines all 11 methods', () => {
    const methodNames: (keyof LocalAgentPort)[] = [
      'createIdentifier',
      'rotateKeys',
      'createInteraction',
      'getKeyState',
      'exportKel',
      'importKel',
      'sign',
      'verify',
      'createRegistry',
      'issueCredential',
      'listCredentials',
    ];
    expect(methodNames).toHaveLength(11);
  });

  it('method return types compile correctly', async () => {
    const mock: LocalAgentPort = {
      createIdentifier: async () => ({ prefix: 'ETest' }),
      rotateKeys: async () => ({ sn: 1 }),
      createInteraction: async () => ({ sn: 2 }),
      getKeyState: async () => ({ prefix: 'ETest', sn: 0, keys: [], transferable: false }),
      exportKel: async () => new Uint8Array(0),
      importKel: async () => {},
      sign: async () => [],
      verify: async () => false,
      createRegistry: async () => 'reg-id',
      issueCredential: async () => 'cred-id',
      listCredentials: async () => [],
    };

    const id = await mock.createIdentifier({ alias: 'test' });
    expect(id.prefix).toBe('ETest');

    const rot = await mock.rotateKeys('test');
    expect(rot.sn).toBe(1);

    const ixn = await mock.createInteraction('test', [{ d: 'seal' }]);
    expect(ixn.sn).toBe(2);

    const ks = await mock.getKeyState('test');
    expect(ks.keys).toEqual([]);
    expect(ks.transferable).toBe(false);

    const kel = await mock.exportKel('test');
    expect(kel).toBeInstanceOf(Uint8Array);

    const sigs = await mock.sign('test', 'hello');
    expect(sigs).toEqual([]);

    const valid = await mock.verify('ETest', 'hello', []);
    expect(valid).toBe(false);

    const creds = await mock.listCredentials('test');
    expect(creds).toEqual([]);
  });
});
