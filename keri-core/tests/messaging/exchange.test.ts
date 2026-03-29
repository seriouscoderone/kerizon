import { describe, it, expect } from 'vitest';
import { exchange } from '../../src/messaging/exchange.js';

describe('exchange', () => {
  const config = {
    route: '/echo',
    sender: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    payload: { msg: 'hello' },
    datetime: '2026-01-01T00:00:00.000000+00:00',
  };

  it('creates an exn with correct ilk and route', () => {
    const serder = exchange(config);
    expect(serder.ilk).toBe('exn');
    expect(serder.ked['r']).toBe('/echo');
  });

  it('links to prior via p field', () => {
    const prior = 'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg';
    const serder = exchange({ ...config, prior });
    expect(serder.ked['p']).toBe(prior);
  });

  it('includes embeds in e field', () => {
    const embeds = { iss: { v: 'KERI10JSON000000_', t: 'iss' } };
    const serder = exchange({ ...config, embeds });
    expect(serder.ked['e']).toEqual(embeds);
  });

  it('SAID verifies', () => {
    const serder = exchange(config);
    expect(serder.verifySaid()).toBe(true);
  });
});
