import Datastore from 'nedb-promises';
import type { WitnessStore } from './types.js';

interface EventDoc {
  prefix: string;
  sn: number;
  said: string;
  raw: string;
  sigs: string[];
}

interface KeyStateDoc {
  prefix: string;
  state: Record<string, unknown>;
}

interface ReceiptDoc {
  eventSaid: string;
  signerAid: string;
  signature: string;
}

interface IdentityDoc {
  _tag: 'witness-identity';
  signerQb64: string;
  prefix: string;
}

export class NedbStore implements WitnessStore {
  private events: Datastore<EventDoc>;
  private keyStates: Datastore<KeyStateDoc>;
  private receipts: Datastore<ReceiptDoc>;
  private identity: Datastore<IdentityDoc>;

  constructor(dbDir: string) {
    this.events = Datastore.create({ filename: `${dbDir}/events.db`, autoload: true }) as Datastore<EventDoc>;
    this.keyStates = Datastore.create({ filename: `${dbDir}/keyStates.db`, autoload: true }) as Datastore<KeyStateDoc>;
    this.receipts = Datastore.create({ filename: `${dbDir}/receipts.db`, autoload: true }) as Datastore<ReceiptDoc>;
    this.identity = Datastore.create({ filename: `${dbDir}/identity.db`, autoload: true }) as Datastore<IdentityDoc>;
  }

  async putEvent(prefix: string, sn: number, said: string, raw: string, sigs: string[]): Promise<void> {
    await this.events.insert({ prefix, sn, said, raw, sigs } satisfies EventDoc);
  }

  async getEvents(prefix: string): Promise<Array<{ sn: number; said: string; raw: string; sigs: string[] }>> {
    const docs = await this.events.find({ prefix }).sort({ sn: 1 }) as EventDoc[];
    return docs.map(({ sn, said, raw, sigs }) => ({ sn, said, raw, sigs }));
  }

  async putKeyState(prefix: string, state: Record<string, unknown>): Promise<void> {
    await this.keyStates.update(
      { prefix },
      { prefix, state } satisfies KeyStateDoc,
      { upsert: true },
    );
  }

  async getKeyState(prefix: string): Promise<Record<string, unknown> | null> {
    const doc = await this.keyStates.findOne({ prefix }) as KeyStateDoc | null;
    return doc ? doc.state : null;
  }

  async putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void> {
    await this.receipts.insert({
      eventSaid,
      signerAid: receipt.signerAid,
      signature: receipt.signature,
    } satisfies ReceiptDoc);
  }

  async getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>> {
    const docs = await this.receipts.find({ eventSaid }) as ReceiptDoc[];
    return docs.map(({ signerAid, signature }) => ({ signerAid, signature }));
  }

  async putWitnessIdentity(signerQb64: string, prefix: string): Promise<void> {
    await this.identity.update(
      { _tag: 'witness-identity' },
      { _tag: 'witness-identity', signerQb64, prefix } satisfies IdentityDoc,
      { upsert: true },
    );
  }

  async getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null> {
    const doc = await this.identity.findOne({ _tag: 'witness-identity' }) as IdentityDoc | null;
    return doc ? { signerQb64: doc.signerQb64, prefix: doc.prefix } : null;
  }

  async close(): Promise<void> {
    // nedb-promises doesn't have an explicit close; no-op for interface compliance
  }
}
