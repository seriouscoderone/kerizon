import { describe, it, expect } from 'vitest';
import { createRegistry, createUpdate } from '../../src/credential-lifecycle/registry.js';

describe('createRegistry', () => {
  it('produces rip with i==d and n=="0"', () => {
    const serder = createRegistry({
      issuerAid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    });
    expect(serder.ked['t']).toBe('rip');
    expect(serder.ked['i']).toBe(serder.ked['d']);
    expect(serder.ked['n']).toBe('0');
  });

  it('has a valid SAID', () => {
    const serder = createRegistry({
      issuerAid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    });
    expect(serder.verifySaid()).toBe(true);
  });

  it('records the issuer aid in ii field', () => {
    const aid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
    const serder = createRegistry({ issuerAid: aid });
    expect(serder.ked['ii']).toBe(aid);
  });
});

describe('createUpdate', () => {
  it('produces upd for issuance', () => {
    const serder = createUpdate({
      registrySaid: 'ERegistrySaid_________________________________',
      credentialSaid: 'ECredentialSaid_______________________________',
      priorSaid: 'EPriorSaid____________________________________',
      sn: 1,
      targetState: 'Issued',
    });
    expect(serder.ked['t']).toBe('upd');
    expect(serder.ked['ts']).toBe('Issued');
    expect(serder.ked['rd']).toBe('ERegistrySaid_________________________________');
    expect(serder.ked['ta']).toBe('ECredentialSaid_______________________________');
  });

  it('produces upd for revocation with p=prior', () => {
    const priorSaid = 'EPriorSaid____________________________________';
    const serder = createUpdate({
      registrySaid: 'ERegistrySaid_________________________________',
      credentialSaid: 'ECredentialSaid_______________________________',
      priorSaid,
      sn: 2,
      targetState: 'Revoked',
    });
    expect(serder.ked['t']).toBe('upd');
    expect(serder.ked['ts']).toBe('Revoked');
    expect(serder.ked['p']).toBe(priorSaid);
  });

  it('has a valid SAID', () => {
    const serder = createUpdate({
      registrySaid: 'ERegistrySaid_________________________________',
      credentialSaid: 'ECredentialSaid_______________________________',
      priorSaid: 'EPriorSaid____________________________________',
      sn: 1,
      targetState: 'Issued',
    });
    expect(serder.verifySaid()).toBe(true);
  });

  it('encodes sn as hex in n field', () => {
    const serder = createUpdate({
      registrySaid: 'ERegistrySaid_________________________________',
      credentialSaid: 'ECredentialSaid_______________________________',
      priorSaid: 'EPriorSaid____________________________________',
      sn: 16,
      targetState: 'Issued',
    });
    expect(serder.ked['n']).toBe('10');
  });
});
