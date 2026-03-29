import { describe, it, expect } from 'vitest';
import { verifyCredentialArtifacts, verifyProofChain } from '../../src/credential-proof/verify.js';

describe('verifyCredentialArtifacts', () => {
  it('valid artifacts return verified: true', () => {
    const result = verifyCredentialArtifacts({
      acdcSaid: 'EAcdc111',
      telEventSaid: 'ETel222',
      kelSealSaid: 'EKel333',
      issuerAid: 'DIssuer444',
    });
    expect(result.verified).toBe(true);
  });

  it('missing acdcSaid returns verified: false', () => {
    const result = verifyCredentialArtifacts({
      acdcSaid: '',
      telEventSaid: 'ETel222',
      kelSealSaid: 'EKel333',
      issuerAid: 'DIssuer444',
    });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.reason).toContain('acdcSaid');
    }
  });
});

describe('verifyProofChain', () => {
  it('valid chain returns verified: true', () => {
    const result = verifyProofChain({
      acdcSaid: 'EAcdc111',
      telRegistrySaid: 'EReg222',
      telSn: 1,
      kelAnchorSaid: 'EAnc333',
      issuerAid: 'DIssuer444',
    });
    expect(result.verified).toBe(true);
  });

  it('telSn=0 fails', () => {
    const result = verifyProofChain({
      acdcSaid: 'EAcdc111',
      telRegistrySaid: 'EReg222',
      telSn: 0,
      kelAnchorSaid: 'EAnc333',
      issuerAid: 'DIssuer444',
    });
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.reason).toContain('telSn');
    }
  });
});
