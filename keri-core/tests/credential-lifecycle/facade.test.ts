import { describe, it, expect } from 'vitest';
import { CredentialLifecycle } from '../../src/credential-lifecycle/facade.js';

const ISSUER = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
const CRED_SAID = 'ECredSaid_____________________________________';

describe('CredentialLifecycle', () => {
  it('createRegistry returns serder + regid', () => {
    const lc = new CredentialLifecycle();
    const { serder, regid } = lc.createRegistry({
      issuerAid: ISSUER,
      name: 'test-reg',
    });

    expect(serder.said).toBeTruthy();
    expect(regid).toBe(serder.said);
    expect(serder.ked['t']).toBe('rip');
  });

  it('issue transitions credential to Issued', () => {
    const lc = new CredentialLifecycle();
    lc.createRegistry({ issuerAid: ISSUER, name: 'test-reg' });

    const serder = lc.issue({
      registryName: 'test-reg',
      credentialSaid: CRED_SAID,
    });

    expect(serder.ked['ts']).toBe('Issued');

    const state = lc.getState('test-reg', CRED_SAID);
    expect(state.state).toBe('Issued');
  });

  it('revoke transitions credential to Revoked', () => {
    const lc = new CredentialLifecycle();
    lc.createRegistry({ issuerAid: ISSUER, name: 'test-reg' });
    lc.issue({ registryName: 'test-reg', credentialSaid: CRED_SAID });

    const serder = lc.revoke({
      registryName: 'test-reg',
      credentialSaid: CRED_SAID,
    });

    expect(serder.ked['ts']).toBe('Revoked');

    const state = lc.getState('test-reg', CRED_SAID);
    expect(state.state).toBe('Revoked');
  });

  it('getState reflects current state', () => {
    const lc = new CredentialLifecycle();
    lc.createRegistry({ issuerAid: ISSUER, name: 'test-reg' });

    // Before issue: NotIssued
    const before = lc.getState('test-reg', CRED_SAID);
    expect(before.state).toBe('NotIssued');

    // After issue: Issued
    lc.issue({ registryName: 'test-reg', credentialSaid: CRED_SAID });
    const after = lc.getState('test-reg', CRED_SAID);
    expect(after.state).toBe('Issued');
  });

  it('revoke before issue throws', () => {
    const lc = new CredentialLifecycle();
    lc.createRegistry({ issuerAid: ISSUER, name: 'test-reg' });

    expect(() =>
      lc.revoke({ registryName: 'test-reg', credentialSaid: CRED_SAID }),
    ).toThrow();
  });

  it('double issue throws', () => {
    const lc = new CredentialLifecycle();
    lc.createRegistry({ issuerAid: ISSUER, name: 'test-reg' });
    lc.issue({ registryName: 'test-reg', credentialSaid: CRED_SAID });

    expect(() =>
      lc.issue({ registryName: 'test-reg', credentialSaid: CRED_SAID }),
    ).toThrow();
  });

  it('unknown registry throws', () => {
    const lc = new CredentialLifecycle();

    expect(() =>
      lc.issue({ registryName: 'nonexistent', credentialSaid: CRED_SAID }),
    ).toThrow('Unknown registry: nonexistent');

    expect(() =>
      lc.revoke({ registryName: 'nonexistent', credentialSaid: CRED_SAID }),
    ).toThrow('Unknown registry: nonexistent');

    expect(() =>
      lc.getState('nonexistent', CRED_SAID),
    ).toThrow('Unknown registry: nonexistent');
  });
});
