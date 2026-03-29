import { describe, it, expect } from 'vitest';
import { query } from '../../src/messaging/query.js';
import { reply } from '../../src/messaging/reply.js';

describe('query', () => {
  it('creates a qry with route and query params', () => {
    const serder = query({
      route: '/logs',
      replyRoute: '/logs/reply',
      query: { i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc' },
      datetime: '2026-01-01T00:00:00.000000+00:00',
    });
    expect(serder.ilk).toBe('qry');
    expect(serder.ked['r']).toBe('/logs');
    expect(serder.ked['rr']).toBe('/logs/reply');
    expect(serder.ked['q']).toEqual({ i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc' });
  });

  it('SAID verifies for qry', () => {
    const serder = query({
      route: '/logs',
      replyRoute: '/logs/reply',
      query: { i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc' },
      datetime: '2026-01-01T00:00:00.000000+00:00',
    });
    expect(serder.verifySaid()).toBe(true);
  });
});

describe('reply', () => {
  it('creates an rpy with route and data', () => {
    const serder = reply({
      route: '/kel/state',
      data: { i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc', s: '0' },
      datetime: '2026-01-01T00:00:00.000000+00:00',
    });
    expect(serder.ilk).toBe('rpy');
    expect(serder.ked['r']).toBe('/kel/state');
    expect(serder.ked['a']).toEqual({ i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc', s: '0' });
  });

  it('SAID verifies for rpy', () => {
    const serder = reply({
      route: '/kel/state',
      data: { i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc', s: '0' },
      datetime: '2026-01-01T00:00:00.000000+00:00',
    });
    expect(serder.verifySaid()).toBe(true);
  });
});
