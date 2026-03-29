import { describe, it, expect } from 'vitest';
import { DuplicityEventLog } from '../../src/integrity/del.js';
import type { DuplicityEvidence } from '../../src/integrity/types.js';

describe('DuplicityEventLog', () => {
  const aid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

  const evidence: DuplicityEvidence = {
    aid,
    sn: 3,
    saidA: 'ESAID_a_______________________________________',
    saidB: 'ESAID_b_______________________________________',
    detectedAt: '2026-03-29T00:00:00Z',
  };

  it('starts empty', () => {
    const del = new DuplicityEventLog(aid);
    expect(del.entries).toEqual([]);
    expect(del.hasDuplicity).toBe(false);
  });

  it('records evidence', () => {
    const del = new DuplicityEventLog(aid);
    del.record(evidence);

    expect(del.entries).toHaveLength(1);
    expect(del.entries[0]).toEqual(evidence);
    expect(del.hasDuplicity).toBe(true);
  });

  it('accumulates multiple entries', () => {
    const del = new DuplicityEventLog(aid);
    const second: DuplicityEvidence = {
      aid,
      sn: 5,
      saidA: 'ESAID_c_______________________________________',
      saidB: 'ESAID_d_______________________________________',
      detectedAt: '2026-03-29T01:00:00Z',
    };

    del.record(evidence);
    del.record(second);

    expect(del.entries).toHaveLength(2);
    expect(del.entries[0]).toEqual(evidence);
    expect(del.entries[1]).toEqual(second);
  });

  it('entries are append-only (read-only copy)', () => {
    const del = new DuplicityEventLog(aid);
    del.record(evidence);

    const snapshot = del.entries;
    expect(snapshot).toHaveLength(1);

    // Mutating the returned array must not affect internal state
    (snapshot as DuplicityEvidence[]).push({
      aid,
      sn: 99,
      saidA: 'ESAID_x_______________________________________',
      saidB: 'ESAID_y_______________________________________',
      detectedAt: '2026-03-29T02:00:00Z',
    });

    expect(del.entries).toHaveLength(1);
  });
});
