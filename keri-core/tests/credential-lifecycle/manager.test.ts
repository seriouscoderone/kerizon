import { describe, it, expect } from 'vitest';
import { RegistryManager } from '../../src/credential-lifecycle/manager.js';
import type { RegistryRecord } from '../../src/credential-lifecycle/types.js';

describe('RegistryManager', () => {
  const REG_SAID = 'ERegistrySaid_________________________________';
  const ISSUER_AID = 'EIssuerAid____________________________________';

  function makeRecord(overrides?: Partial<RegistryRecord>): RegistryRecord {
    return {
      registrySaid: REG_SAID,
      issuerAid: ISSUER_AID,
      name: 'test-registry',
      mode: 'non-blindable',
      createdAt: '2026-03-29T00:00:00.000Z',
      ...overrides,
    };
  }

  it('register + getRegistry by SAID', () => {
    const mgr = new RegistryManager();
    const record = makeRecord();
    mgr.register(record);

    const found = mgr.getRegistry(REG_SAID);
    expect(found).toEqual(record);
  });

  it('getRegistryByName lookup', () => {
    const mgr = new RegistryManager();
    const record = makeRecord();
    mgr.register(record);

    const found = mgr.getRegistryByName('test-registry');
    expect(found).toEqual(record);
  });

  it('getRegistry returns undefined for unknown', () => {
    const mgr = new RegistryManager();
    expect(mgr.getRegistry('EUnknown______________________________________')).toBeUndefined();
  });

  it('getTel returns associated state machine', () => {
    const mgr = new RegistryManager();
    const record = makeRecord();
    mgr.register(record);

    const tel = mgr.getTel(REG_SAID);
    expect(tel).toBeDefined();
    expect(tel!.registrySaid).toBe(REG_SAID);
  });

  it('listRegistries returns all', () => {
    const mgr = new RegistryManager();
    const r1 = makeRecord({ registrySaid: 'EFirst________________________________________', name: 'first' });
    const r2 = makeRecord({ registrySaid: 'ESecond_______________________________________', name: 'second' });
    mgr.register(r1);
    mgr.register(r2);

    const list = mgr.listRegistries();
    expect(list).toHaveLength(2);
    expect(list).toContainEqual(r1);
    expect(list).toContainEqual(r2);
  });

  it('register with blindable mode', () => {
    const mgr = new RegistryManager();
    const record = makeRecord({ mode: 'blindable' });
    mgr.register(record);

    const found = mgr.getRegistry(REG_SAID);
    expect(found!.mode).toBe('blindable');
  });

  it('register with non-blindable mode (default)', () => {
    const mgr = new RegistryManager();
    const record = makeRecord({ mode: 'non-blindable' });
    mgr.register(record);

    const found = mgr.getRegistry(REG_SAID);
    expect(found!.mode).toBe('non-blindable');
  });

  it('duplicate name throws', () => {
    const mgr = new RegistryManager();
    const r1 = makeRecord({ registrySaid: 'EFirst________________________________________', name: 'dup-name' });
    const r2 = makeRecord({ registrySaid: 'ESecond_______________________________________', name: 'dup-name' });
    mgr.register(r1);

    expect(() => mgr.register(r2)).toThrow();
  });
});
