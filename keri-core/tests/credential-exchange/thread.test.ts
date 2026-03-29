import { describe, it, expect } from 'vitest';
import { NegotiationStateMachine } from '../../src/credential-exchange/thread.js';
import { NegotiationState, IPEX_ROUTES } from '../../src/credential-exchange/types.js';
import {
  buildApply,
  buildOffer,
  buildAgree,
  buildGrant,
  buildAdmit,
  buildSpurn,
} from '../../src/credential-exchange/ipex.js';

const SENDER = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
const DT = '2026-01-01T00:00:00.000000+00:00';

function acdc() {
  return { v: 'ACDC10JSON000000_', d: '', i: SENDER, s: 'ESchema' };
}

describe('NegotiationStateMachine', () => {
  it('starts in Idle state', () => {
    const sm = new NegotiationStateMachine();
    expect(sm.state).toBe(NegotiationState.Idle);
  });

  describe('full negotiation flow: Idle -> Applied -> Offered -> Agreed -> Granted -> Admitted', () => {
    it('transitions through the full chain', () => {
      const sm = new NegotiationStateMachine();

      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);
      expect(sm.state).toBe(NegotiationState.Applied);

      const offer = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: apply.said, datetime: DT });
      sm.apply(offer);
      expect(sm.state).toBe(NegotiationState.Offered);

      const agree = buildAgree({ sender: SENDER, prior: offer.said, datetime: DT });
      sm.apply(agree);
      expect(sm.state).toBe(NegotiationState.Agreed);

      const grant = buildGrant({ sender: SENDER, payload: {}, acdc: acdc(), prior: agree.said, datetime: DT });
      sm.apply(grant);
      expect(sm.state).toBe(NegotiationState.Granted);

      const admit = buildAdmit({ sender: SENDER, prior: grant.said, datetime: DT });
      sm.apply(admit);
      expect(sm.state).toBe(NegotiationState.Admitted);
    });
  });

  describe('direct grant flow: Idle -> Granted -> Admitted', () => {
    it('allows grant from Idle', () => {
      const sm = new NegotiationStateMachine();

      const grant = buildGrant({ sender: SENDER, payload: {}, acdc: acdc(), datetime: DT });
      sm.apply(grant);
      expect(sm.state).toBe(NegotiationState.Granted);

      const admit = buildAdmit({ sender: SENDER, prior: grant.said, datetime: DT });
      sm.apply(admit);
      expect(sm.state).toBe(NegotiationState.Admitted);
    });
  });

  describe('spurn from non-terminal states', () => {
    it('spurns from Applied', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);

      const spurn = buildSpurn({ sender: SENDER, prior: apply.said, datetime: DT });
      sm.apply(spurn);
      expect(sm.state).toBe(NegotiationState.Spurned);
    });

    it('spurns from Offered', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);
      const offer = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: apply.said, datetime: DT });
      sm.apply(offer);

      const spurn = buildSpurn({ sender: SENDER, prior: offer.said, datetime: DT });
      sm.apply(spurn);
      expect(sm.state).toBe(NegotiationState.Spurned);
    });

    it('spurns from Agreed', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);
      const offer = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: apply.said, datetime: DT });
      sm.apply(offer);
      const agree = buildAgree({ sender: SENDER, prior: offer.said, datetime: DT });
      sm.apply(agree);

      const spurn = buildSpurn({ sender: SENDER, prior: agree.said, datetime: DT });
      sm.apply(spurn);
      expect(sm.state).toBe(NegotiationState.Spurned);
    });

    it('spurns from Granted', () => {
      const sm = new NegotiationStateMachine();
      const grant = buildGrant({ sender: SENDER, payload: {}, acdc: acdc(), datetime: DT });
      sm.apply(grant);

      const spurn = buildSpurn({ sender: SENDER, prior: grant.said, datetime: DT });
      sm.apply(spurn);
      expect(sm.state).toBe(NegotiationState.Spurned);
    });
  });

  describe('rejects transition from terminal state', () => {
    it('throws when transitioning from Admitted', () => {
      const sm = new NegotiationStateMachine();
      const grant = buildGrant({ sender: SENDER, payload: {}, acdc: acdc(), datetime: DT });
      sm.apply(grant);
      const admit = buildAdmit({ sender: SENDER, prior: grant.said, datetime: DT });
      sm.apply(admit);

      const spurn = buildSpurn({ sender: SENDER, prior: admit.said, datetime: DT });
      expect(() => sm.apply(spurn)).toThrow();
    });

    it('throws when transitioning from Spurned', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);
      const spurn = buildSpurn({ sender: SENDER, prior: apply.said, datetime: DT });
      sm.apply(spurn);

      const offer = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: apply.said, datetime: DT });
      expect(() => sm.apply(offer)).toThrow();
    });
  });

  describe('rejects invalid transitions', () => {
    it('rejects Idle -> Agreed', () => {
      const sm = new NegotiationStateMachine();
      const agree = buildAgree({ sender: SENDER, prior: 'EFakeSaid_placeholder00000000000000000000000', datetime: DT });
      expect(() => sm.apply(agree)).toThrow();
    });

    it('rejects Idle -> Admitted', () => {
      const sm = new NegotiationStateMachine();
      const admit = buildAdmit({ sender: SENDER, prior: 'EFakeSaid_placeholder00000000000000000000000', datetime: DT });
      expect(() => sm.apply(admit)).toThrow();
    });

    it('rejects Applied -> Agreed', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);

      const agree = buildAgree({ sender: SENDER, prior: apply.said, datetime: DT });
      expect(() => sm.apply(agree)).toThrow();
    });
  });

  describe('tracks message chain', () => {
    it('records all messages in history', () => {
      const sm = new NegotiationStateMachine();
      const apply = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      sm.apply(apply);

      const offer = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: apply.said, datetime: DT });
      sm.apply(offer);

      expect(sm.history).toHaveLength(2);
      expect(sm.history[0]).toBe(apply.said);
      expect(sm.history[1]).toBe(offer.said);
    });
  });
});
