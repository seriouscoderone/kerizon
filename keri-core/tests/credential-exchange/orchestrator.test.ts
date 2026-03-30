import { describe, it, expect } from 'vitest';
import { CredentialExchange } from '../../src/credential-exchange/orchestrator.js';
import { NegotiationState, IPEX_ROUTES } from '../../src/credential-exchange/types.js';

const ISSUER = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
const HOLDER = 'EHolderAid____________________________________';
const DT = '2026-01-01T00:00:00.000000+00:00';

function acdc() {
  return { v: 'ACDC10JSON000000_', d: '', i: ISSUER, s: 'ESchema' };
}

describe('CredentialExchange', () => {
  it('initiateIssuance creates grant + thread in Granted state', () => {
    const cx = new CredentialExchange();
    const { grant, threadId } = cx.initiateIssuance({
      issuerAid: ISSUER,
      holderAid: HOLDER,
      acdc: acdc(),
      datetime: DT,
    });

    expect(grant.said).toBeTruthy();
    expect(threadId).toBe(grant.said);

    const thread = cx.getThread(threadId)!;
    expect(thread).toBeDefined();
    expect(thread.state).toBe(NegotiationState.Granted);
  });

  it('processMessage advances thread state', () => {
    const cx = new CredentialExchange();
    const { grant, threadId } = cx.initiateIssuance({
      issuerAid: ISSUER,
      holderAid: HOLDER,
      acdc: acdc(),
      datetime: DT,
    });

    const result = cx.processMessage({
      said: 'EAdmitSaid____________________________________',
      route: IPEX_ROUTES.admit,
      threadId,
    });

    expect(result.state).toBe(NegotiationState.Admitted);
  });

  it('getThread returns thread by ID', () => {
    const cx = new CredentialExchange();
    const { threadId } = cx.initiateIssuance({
      issuerAid: ISSUER,
      holderAid: HOLDER,
      acdc: acdc(),
      datetime: DT,
    });

    const thread = cx.getThread(threadId);
    expect(thread).toBeDefined();
    expect(thread!.state).toBe(NegotiationState.Granted);

    // Unknown thread
    expect(cx.getThread('EUnknown______________________________________')).toBeUndefined();
  });

  it('full flow: grant -> admit', () => {
    const cx = new CredentialExchange();
    const { threadId } = cx.initiateIssuance({
      issuerAid: ISSUER,
      holderAid: HOLDER,
      acdc: acdc(),
      datetime: DT,
    });

    // Thread should be in Granted state after issuance
    expect(cx.getThread(threadId)!.state).toBe(NegotiationState.Granted);

    // Holder admits
    const result = cx.processMessage({
      said: 'EAdmitSaid____________________________________',
      route: IPEX_ROUTES.admit,
      threadId,
    });

    expect(result.state).toBe(NegotiationState.Admitted);
  });

  it('processMessage with unknown threadId creates new thread', () => {
    const cx = new CredentialExchange();

    // Process a grant message with no existing thread
    const result = cx.processMessage({
      said: 'ENewGrant_____________________________________',
      route: IPEX_ROUTES.grant,
      threadId: 'ENewThread____________________________________',
    });

    expect(result.state).toBe(NegotiationState.Granted);
    expect(cx.getThread('ENewThread____________________________________')).toBeDefined();
  });
});
