import { describe, it, expect } from 'vitest';
import { parseOobi, formatOobi } from '../src/oobi.js';

describe('parseOobi', () => {
  it('extracts cid and role from standard URL', () => {
    const result = parseOobi('http://localhost:5642/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc/witness');
    expect(result.cid).toBe('ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc');
    expect(result.role).toBe('witness');
    expect(result.eid).toBeUndefined();
    expect(result.url).toBe('http://localhost:5642/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc/witness');
  });

  it('extracts cid + role + eid', () => {
    const result = parseOobi(
      'http://localhost:5642/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc/witness/EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    );
    expect(result.cid).toBe('ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc');
    expect(result.role).toBe('witness');
    expect(result.eid).toBe('EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj');
  });

  it('handles well-known format', () => {
    const result = parseOobi(
      'http://localhost:5642/.well-known/keri/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    );
    expect(result.cid).toBe('ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc');
    expect(result.url).toBe(
      'http://localhost:5642/.well-known/keri/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    );
  });

  it('returns just url for unknown format', () => {
    const result = parseOobi('http://localhost:5642/other/path');
    expect(result.url).toBe('http://localhost:5642/other/path');
    expect(result.cid).toBeUndefined();
    expect(result.role).toBeUndefined();
    expect(result.eid).toBeUndefined();
  });
});

describe('formatOobi', () => {
  it('produces correct URL with role', () => {
    const url = formatOobi('http://localhost:5642', {
      cid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      role: 'witness',
    });
    expect(url).toBe('http://localhost:5642/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc/witness');
  });

  it('produces correct URL with cid + role + eid', () => {
    const url = formatOobi('http://localhost:5642', {
      cid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      role: 'witness',
      eid: 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    });
    expect(url).toBe(
      'http://localhost:5642/oobi/ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc/witness/EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    );
  });

  it('round-trip: parse(format(parts)) recovers parts', () => {
    const parts = {
      cid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      role: 'witness' as const,
      eid: 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    };
    const url = formatOobi('http://localhost:5642', parts);
    const parsed = parseOobi(url);
    expect(parsed.cid).toBe(parts.cid);
    expect(parsed.role).toBe(parts.role);
    expect(parsed.eid).toBe(parts.eid);
  });
});
