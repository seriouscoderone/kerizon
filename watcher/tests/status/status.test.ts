import { describe, it, expect } from 'vitest';
import { createDuplicityStatus } from '../../src/status.js';

describe('createDuplicityStatus', () => {
  const aid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

  it('no evidence means not duplicitous', () => {
    const status = createDuplicityStatus(aid, []);
    expect(status.isDuplicitous).toBe(false);
    expect(status.evidence).toEqual([]);
  });

  it('one SAID means not duplicitous', () => {
    const status = createDuplicityStatus(aid, ['EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg']);
    expect(status.isDuplicitous).toBe(false);
    expect(status.evidence).toHaveLength(1);
  });

  it('two SAIDs means duplicitous', () => {
    const status = createDuplicityStatus(aid, [
      'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg',
      'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    ]);
    expect(status.isDuplicitous).toBe(true);
    expect(status.evidence).toHaveLength(2);
  });
});
