import { describe, it, expect, vi } from 'vitest';
import { EscrowStore } from '../../src/identity/escrow.js';
import type { EscrowedEvent } from '../../src/identity/types.js';

function makeEvent(overrides: Partial<EscrowedEvent> = {}): EscrowedEvent {
  return {
    escrowType: 'OOE',
    aid: 'EAbcdefghijklmnopqrstuvwxyz012345678901234567',
    sn: 1,
    eventSaid: 'EXyz0000000000000000000000000000000000000000',
    escrowedAt: Date.now(),
    ...overrides,
  };
}

describe('EscrowStore', () => {
  it('add stores event', () => {
    const store = new EscrowStore();
    const event = makeEvent();
    store.add(event);
    expect(store.size).toBe(1);
  });

  it('drain returns matching and removes them', () => {
    const store = new EscrowStore();
    const aid = 'EAbcdefghijklmnopqrstuvwxyz012345678901234567';
    const e1 = makeEvent({ aid, sn: 1 });
    const e2 = makeEvent({ aid, sn: 1, escrowType: 'PSE' });
    const e3 = makeEvent({ aid, sn: 2 });
    store.add(e1);
    store.add(e2);
    store.add(e3);

    const drained = store.drain(aid, 1);
    expect(drained).toEqual([e1, e2]);
    expect(store.size).toBe(1);
  });

  it('drain returns empty for non-matching', () => {
    const store = new EscrowStore();
    store.add(makeEvent({ sn: 5 }));

    const drained = store.drain('ENonexistent00000000000000000000000000000000', 99);
    expect(drained).toEqual([]);
    expect(store.size).toBe(1);
  });

  it('getByType filters correctly', () => {
    const store = new EscrowStore();
    store.add(makeEvent({ escrowType: 'OOE' }));
    store.add(makeEvent({ escrowType: 'PSE' }));
    store.add(makeEvent({ escrowType: 'OOE' }));
    store.add(makeEvent({ escrowType: 'LDE' }));

    const ooe = store.getByType('OOE');
    expect(ooe).toHaveLength(2);
    ooe.forEach(e => expect(e.escrowType).toBe('OOE'));

    const pse = store.getByType('PSE');
    expect(pse).toHaveLength(1);

    const pwe = store.getByType('PWE');
    expect(pwe).toHaveLength(0);
  });

  it('sweepTimeout removes old entries', () => {
    const store = new EscrowStore();
    const old = makeEvent({ escrowedAt: Date.now() - 10_000 });
    store.add(old);

    const expired = store.sweepTimeout(5_000);
    expect(expired).toEqual([old]);
    expect(store.size).toBe(0);
  });

  it('sweepTimeout keeps fresh entries', () => {
    const store = new EscrowStore();
    const fresh = makeEvent({ escrowedAt: Date.now() });
    store.add(fresh);

    const expired = store.sweepTimeout(60_000);
    expect(expired).toEqual([]);
    expect(store.size).toBe(1);
  });

  it('size tracks count', () => {
    const store = new EscrowStore();
    expect(store.size).toBe(0);
    store.add(makeEvent());
    expect(store.size).toBe(1);
    store.add(makeEvent());
    expect(store.size).toBe(2);
    store.drain(makeEvent().aid, makeEvent().sn);
    expect(store.size).toBe(0);
  });
});
