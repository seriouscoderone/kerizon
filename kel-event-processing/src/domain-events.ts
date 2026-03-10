/** Successful acceptance in direct mode — infrastructure should send receipt. */
export interface EventAccepted {
  type: "EventAccepted";
  prefix: string;
  sn: number;
  said: string;
}

/** Successful acceptance in indirect mode — infrastructure should notify watchers. */
export interface EventNoticed {
  type: "EventNoticed";
  prefix: string;
  sn: number;
  said: string;
}

/** Locally-witnessed event accepted — infrastructure should generate witness receipt. */
export interface WitnessReceiptNeeded {
  type: "WitnessReceiptNeeded";
  prefix: string;
  sn: number;
  said: string;
}

/** Escrow timeout for missing event — infrastructure should query peers. */
export interface EventQueryNeeded {
  type: "EventQueryNeeded";
  prefix: string;
  sequenceNumber: number;
}

/** Replay mode: first-seen ordinal mismatch — infrastructure should flag. */
export interface CloneMismatchDetected {
  type: "CloneMismatchDetected";
  prefix: string;
  sn: number;
  said: string;
  expectedOrdinal: number;
  actualOrdinal: number;
}

/** Remote signature for locally-controlled group member. */
export interface RemoteGroupSignatureReceived {
  type: "RemoteGroupSignatureReceived";
  prefix: string;
  sn: number;
  said: string;
  index: number;
}

/** Discriminated union of all domain event types. */
export type DomainEvent =
  | EventAccepted
  | EventNoticed
  | WitnessReceiptNeeded
  | EventQueryNeeded
  | CloneMismatchDetected
  | RemoteGroupSignatureReceived;

/**
 * DomainEventBus — FIFO queue of typed domain events.
 *
 * The EventProcessor pushes domain events. The infrastructure layer drains them.
 * Ordering guarantee: events are delivered in the order they were pushed.
 */
export class DomainEventBus {
  private queue: DomainEvent[] = [];

  /** Add a domain event to the FIFO queue. */
  push(event: DomainEvent): void {
    this.queue.push(event);
  }

  /** Remove and return the next domain event, or undefined if empty. */
  pull(): DomainEvent | undefined {
    return this.queue.shift();
  }

  /** Remove and return all pending domain events. */
  drain(): DomainEvent[] {
    const events = this.queue;
    this.queue = [];
    return events;
  }

  /** Check if the queue is empty. */
  isEmpty(): boolean {
    return this.queue.length === 0;
  }
}
