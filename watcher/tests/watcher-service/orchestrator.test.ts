import { describe, it, expect } from 'vitest';
import { WatcherService } from '../../src/orchestrator.js';

const AID = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

describe('WatcherService', () => {
  it('no duplicity when KELs match', () => {
    const ws = new WatcherService();
    const eventsA = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1________________________________________' },
    ];
    const eventsB = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1________________________________________' },
    ];

    const status = ws.crossCheck(AID, eventsA, eventsB);
    expect(status.isDuplicitous).toBe(false);
    expect(status.evidence).toHaveLength(0);
  });

  it('detects fork at specific sn', () => {
    const ws = new WatcherService();
    const eventsA = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1A_______________________________________' },
    ];
    const eventsB = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1B_______________________________________' },
    ];

    const status = ws.crossCheck(AID, eventsA, eventsB);
    expect(status.isDuplicitous).toBe(true);
    expect(status.evidence).toContain('ESaid1A_______________________________________');
    expect(status.evidence).toContain('ESaid1B_______________________________________');
  });

  it('records evidence in DEL', () => {
    const ws = new WatcherService();
    const eventsA = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1A_______________________________________' },
    ];
    const eventsB = [
      { sn: 0, said: 'ESaid0________________________________________' },
      { sn: 1, said: 'ESaid1B_______________________________________' },
    ];

    ws.crossCheck(AID, eventsA, eventsB);

    const del = ws.getDel(AID);
    expect(del.entries).toHaveLength(1);
    expect(del.entries[0].sn).toBe(1);
    expect(del.entries[0].saidA).toBe('ESaid1A_______________________________________');
    expect(del.entries[0].saidB).toBe('ESaid1B_______________________________________');
  });

  it('hasDuplicity returns true after fork detected', () => {
    const ws = new WatcherService();
    const eventsA = [{ sn: 0, said: 'ESaidA________________________________________' }];
    const eventsB = [{ sn: 0, said: 'ESaidB________________________________________' }];

    expect(ws.hasDuplicity(AID)).toBe(false);
    ws.crossCheck(AID, eventsA, eventsB);
    expect(ws.hasDuplicity(AID)).toBe(true);
  });

  it('clean check for unknown AID', () => {
    const ws = new WatcherService();
    expect(ws.hasDuplicity('EUnknownAid___________________________________')).toBe(false);

    const del = ws.getDel('EUnknownAid___________________________________');
    expect(del.hasDuplicity).toBe(false);
    expect(del.entries).toHaveLength(0);
  });
});
