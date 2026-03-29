import { describe, it, expect } from 'vitest';
import type {
  EventSubmissionResult,
  KERLResponse,
  WitnessServicePort,
} from '../../src/witness-api/types.js';

describe('EventSubmissionResult', () => {
  it('represents a receipted status', () => {
    const result: EventSubmissionResult = {
      status: 'receipted',
      eventSaid: 'ESAID_event___________________________________',
      receiptSignature: 'sig_data_here',
    };
    expect(result.status).toBe('receipted');
    expect(result.eventSaid).toBeDefined();
    expect('receiptSignature' in result).toBe(true);
  });

  it('represents an escrowed status', () => {
    const result: EventSubmissionResult = {
      status: 'escrowed',
      eventSaid: 'ESAID_event___________________________________',
      reason: 'missing witness receipts',
    };
    expect(result.status).toBe('escrowed');
    expect(result.reason).toBe('missing witness receipts');
  });

  it('represents a rejected status', () => {
    const result: EventSubmissionResult = {
      status: 'rejected',
      eventSaid: 'ESAID_event___________________________________',
      reason: 'stale sequence number',
    };
    expect(result.status).toBe('rejected');
    expect(result.reason).toBe('stale sequence number');
  });
});

describe('KERLResponse', () => {
  it('holds an ordered list of event entries', () => {
    const response: KERLResponse = {
      aid: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      events: [
        { said: 'ESAID_icp_____________________________________', sn: 0, receipted: true },
        { said: 'ESAID_ixn_____________________________________', sn: 1, receipted: true },
        { said: 'ESAID_rot_____________________________________', sn: 2, receipted: false },
      ],
    };

    expect(response.events).toHaveLength(3);
    expect(response.events[0].sn).toBe(0);
    expect(response.events[2].receipted).toBe(false);
  });

  it('sequence numbers are monotonically increasing', () => {
    const events = [
      { said: 'ESAID_0_______________________________________', sn: 0, receipted: true },
      { said: 'ESAID_1_______________________________________', sn: 1, receipted: true },
      { said: 'ESAID_2_______________________________________', sn: 2, receipted: true },
    ];

    for (let i = 1; i < events.length; i++) {
      expect(events[i].sn).toBeGreaterThan(events[i - 1].sn);
    }
  });
});

describe('WitnessServicePort', () => {
  it('can be implemented as a mock', () => {
    const mock: WitnessServicePort = {
      submitEvent: async (_msg: Uint8Array) => ({
        status: 'receipted' as const,
        eventSaid: 'ESAID_test____________________________________',
        receiptSignature: 'mock_sig',
      }),
      getReceipt: async (_prefix: string) => 'mock_receipt_cesr',
      queryKerl: async (prefix: string) => ({
        aid: prefix,
        events: [],
      }),
      resolveOobi: async () => new Uint8Array(0),
    };

    expect(mock.submitEvent).toBeDefined();
    expect(mock.getReceipt).toBeDefined();
    expect(mock.queryKerl).toBeDefined();
    expect(mock.resolveOobi).toBeDefined();
  });
});
