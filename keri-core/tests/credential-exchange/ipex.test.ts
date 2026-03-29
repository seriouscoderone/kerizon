import { describe, it, expect } from 'vitest';
import {
  buildApply,
  buildOffer,
  buildAgree,
  buildGrant,
  buildAdmit,
  buildSpurn,
} from '../../src/credential-exchange/ipex.js';
import { IPEX_ROUTES } from '../../src/credential-exchange/types.js';

const SENDER = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
const PRIOR = 'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg';
const DT = '2026-01-01T00:00:00.000000+00:00';

describe('IPEX message builders', () => {
  describe('buildApply', () => {
    it('produces the /ipex/apply route', () => {
      const serder = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.apply);
    });

    it('has ilk exn', () => {
      const serder = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      expect(serder.ilk).toBe('exn');
    });

    it('has a valid SAID', () => {
      const serder = buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('buildOffer', () => {
    it('produces the /ipex/offer route', () => {
      const serder = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: PRIOR, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.offer);
    });

    it('has a valid SAID', () => {
      const serder = buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: PRIOR, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('buildAgree', () => {
    it('produces the /ipex/agree route', () => {
      const serder = buildAgree({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.agree);
    });

    it('sets p field to prior SAID', () => {
      const serder = buildAgree({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.ked['p']).toBe(PRIOR);
    });

    it('has a valid SAID', () => {
      const serder = buildAgree({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('buildGrant', () => {
    it('produces the /ipex/grant route', () => {
      const acdc = { v: 'ACDC10JSON000000_', d: '', i: SENDER, s: 'ESchema' };
      const serder = buildGrant({ sender: SENDER, payload: {}, acdc, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.grant);
    });

    it('embeds acdc in e field', () => {
      const acdc = { v: 'ACDC10JSON000000_', d: '', i: SENDER, s: 'ESchema' };
      const serder = buildGrant({ sender: SENDER, payload: {}, acdc, datetime: DT });
      expect(serder.ked['e']).toEqual({ acdc });
    });

    it('has a valid SAID', () => {
      const acdc = { v: 'ACDC10JSON000000_', d: '', i: SENDER, s: 'ESchema' };
      const serder = buildGrant({ sender: SENDER, payload: {}, acdc, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('buildAdmit', () => {
    it('produces the /ipex/admit route', () => {
      const serder = buildAdmit({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.admit);
    });

    it('sets p field to prior SAID', () => {
      const serder = buildAdmit({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.ked['p']).toBe(PRIOR);
    });

    it('has a valid SAID', () => {
      const serder = buildAdmit({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('buildSpurn', () => {
    it('produces the /ipex/spurn route', () => {
      const serder = buildSpurn({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.ked['r']).toBe(IPEX_ROUTES.spurn);
    });

    it('has a valid SAID', () => {
      const serder = buildSpurn({ sender: SENDER, prior: PRIOR, datetime: DT });
      expect(serder.verifySaid()).toBe(true);
    });
  });

  describe('all builders produce valid SAIDs', () => {
    it('every IPEX message type has a verifiable SAID', () => {
      const acdc = { v: 'ACDC10JSON000000_', d: '', i: SENDER, s: 'ESchema' };
      const messages = [
        buildApply({ sender: SENDER, payload: { schema: 'ESchema' }, datetime: DT }),
        buildOffer({ sender: SENDER, payload: { schema: 'ESchema' }, prior: PRIOR, datetime: DT }),
        buildAgree({ sender: SENDER, prior: PRIOR, datetime: DT }),
        buildGrant({ sender: SENDER, payload: {}, acdc, datetime: DT }),
        buildAdmit({ sender: SENDER, prior: PRIOR, datetime: DT }),
        buildSpurn({ sender: SENDER, prior: PRIOR, datetime: DT }),
      ];
      for (const m of messages) {
        expect(m.verifySaid()).toBe(true);
      }
    });
  });
});
