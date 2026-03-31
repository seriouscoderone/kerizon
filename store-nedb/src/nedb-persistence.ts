/**
 * NedbPersistence — NeDB-backed implementation of PersistencePort.
 *
 * Stores data in flat files via nedb-promises. Each logical collection
 * (events, keyStates, etc.) gets its own `.db` file in the provided
 * directory.
 */

import Datastore from 'nedb-promises';
import type { PersistencePort, SerializedKeyState } from '@kerizon/keri-core';

// ── Document shapes ──────────────────────────────────────────────

interface EventDoc {
  _collection: 'event';
  prefix: string;
  sn: number;
  said: string;
  raw: string;
  sigs: string[];
}

interface KeyStateDoc {
  _collection: 'keyState';
  prefix: string;
  state: SerializedKeyState;
}

interface AliasDoc {
  _collection: 'alias';
  alias: string;
  prefix: string;
}

interface SignerDoc {
  _collection: 'signer';
  prefix: string;
  alias: string;
  currentQb64s: string[];
  nextQb64s: string[];
}

interface ReceiptDoc {
  _collection: 'receipt';
  eventSaid: string;
  signerAid: string;
  signature: string;
}

interface RegistryDoc {
  _collection: 'registry';
  name: string;
  said: string;
  lastSaid: string;
  lastSn: number;
}

interface CredentialDoc {
  _collection: 'credential';
  said: string;
  registrySaid: string;
  state: string;
  raw: string;
}

interface EndpointDoc {
  _collection: 'endpoint';
  aid: string;
  url: string;
}

interface IdentityDoc {
  _collection: 'witnessIdentity';
  _tag: 'witness-identity';
  signerQb64: string;
  prefix: string;
}

// ── Implementation ───────────────────────────────────────────────

export class NedbPersistence implements PersistencePort {
  private events: Datastore<EventDoc>;
  private keyStates: Datastore<KeyStateDoc>;
  private aliases: Datastore<AliasDoc>;
  private signers: Datastore<SignerDoc>;
  private receipts: Datastore<ReceiptDoc>;
  private registries: Datastore<RegistryDoc>;
  private credentials: Datastore<CredentialDoc>;
  private endpoints: Datastore<EndpointDoc>;
  private identity: Datastore<IdentityDoc>;

  private constructor(
    events: Datastore<EventDoc>,
    keyStates: Datastore<KeyStateDoc>,
    aliases: Datastore<AliasDoc>,
    signers: Datastore<SignerDoc>,
    receipts: Datastore<ReceiptDoc>,
    registries: Datastore<RegistryDoc>,
    credentials: Datastore<CredentialDoc>,
    endpoints: Datastore<EndpointDoc>,
    identity: Datastore<IdentityDoc>,
  ) {
    this.events = events;
    this.keyStates = keyStates;
    this.aliases = aliases;
    this.signers = signers;
    this.receipts = receipts;
    this.registries = registries;
    this.credentials = credentials;
    this.endpoints = endpoints;
    this.identity = identity;
  }

  /**
   * Create a NedbPersistence backed by files in `dbDir`.
   *
   * All datastores are loaded before the instance is returned, so there
   * are no lingering background promises from autoload.
   */
  static async create(dbDir: string): Promise<NedbPersistence> {
    const stores = [
      Datastore.create({ filename: `${dbDir}/events.db` }) as Datastore<EventDoc>,
      Datastore.create({ filename: `${dbDir}/keyStates.db` }) as Datastore<KeyStateDoc>,
      Datastore.create({ filename: `${dbDir}/aliases.db` }) as Datastore<AliasDoc>,
      Datastore.create({ filename: `${dbDir}/signers.db` }) as Datastore<SignerDoc>,
      Datastore.create({ filename: `${dbDir}/receipts.db` }) as Datastore<ReceiptDoc>,
      Datastore.create({ filename: `${dbDir}/registries.db` }) as Datastore<RegistryDoc>,
      Datastore.create({ filename: `${dbDir}/credentials.db` }) as Datastore<CredentialDoc>,
      Datastore.create({ filename: `${dbDir}/endpoints.db` }) as Datastore<EndpointDoc>,
      Datastore.create({ filename: `${dbDir}/identity.db` }) as Datastore<IdentityDoc>,
    ];

    await Promise.all(stores.map(s => s.load()));

    return new NedbPersistence(
      stores[0] as Datastore<EventDoc>,
      stores[1] as Datastore<KeyStateDoc>,
      stores[2] as Datastore<AliasDoc>,
      stores[3] as Datastore<SignerDoc>,
      stores[4] as Datastore<ReceiptDoc>,
      stores[5] as Datastore<RegistryDoc>,
      stores[6] as Datastore<CredentialDoc>,
      stores[7] as Datastore<EndpointDoc>,
      stores[8] as Datastore<IdentityDoc>,
    );
  }

  // ── KEL Events ──

  async putEvent(prefix: string, sn: number, said: string, raw: string, sigs: string[]): Promise<void> {
    await this.events.insert({ _collection: 'event', prefix, sn, said, raw, sigs });
  }

  async getEvents(prefix: string): Promise<Array<{ sn: number; said: string; raw: string; sigs: string[] }>> {
    const docs = await this.events.find({ prefix }).sort({ sn: 1 }) as EventDoc[];
    return docs.map(({ sn, said, raw, sigs }) => ({ sn, said, raw, sigs }));
  }

  async getEvent(prefix: string, sn: number): Promise<{ said: string; raw: string; sigs: string[] } | null> {
    const doc = await this.events.findOne({ prefix, sn }) as EventDoc | null;
    return doc ? { said: doc.said, raw: doc.raw, sigs: doc.sigs } : null;
  }

  // ── Key State ──

  async putKeyState(prefix: string, state: SerializedKeyState): Promise<void> {
    await this.keyStates.update(
      { prefix },
      { _collection: 'keyState', prefix, state } satisfies KeyStateDoc,
      { upsert: true },
    );
  }

  async getKeyState(prefix: string): Promise<SerializedKeyState | null> {
    const doc = await this.keyStates.findOne({ prefix }) as KeyStateDoc | null;
    return doc ? doc.state : null;
  }

  // ── Aliases ──

  async putAlias(alias: string, prefix: string): Promise<void> {
    await this.aliases.update(
      { alias },
      { _collection: 'alias', alias, prefix } satisfies AliasDoc,
      { upsert: true },
    );
  }

  async getPrefix(alias: string): Promise<string | null> {
    const doc = await this.aliases.findOne({ alias }) as AliasDoc | null;
    return doc ? doc.prefix : null;
  }

  async listAliases(): Promise<Array<{ alias: string; prefix: string }>> {
    const docs = await this.aliases.find({}) as AliasDoc[];
    return docs.map(({ alias, prefix }) => ({ alias, prefix }));
  }

  // ── Signing Keys ──

  async putSigners(prefix: string, data: { alias: string; currentQb64s: string[]; nextQb64s: string[] }): Promise<void> {
    await this.signers.update(
      { prefix },
      { _collection: 'signer', prefix, ...data } satisfies SignerDoc,
      { upsert: true },
    );
  }

  async getSigners(prefix: string): Promise<{ alias: string; currentQb64s: string[]; nextQb64s: string[] } | null> {
    const doc = await this.signers.findOne({ prefix }) as SignerDoc | null;
    return doc ? { alias: doc.alias, currentQb64s: doc.currentQb64s, nextQb64s: doc.nextQb64s } : null;
  }

  // ── Receipts ──

  async putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void> {
    await this.receipts.insert({
      _collection: 'receipt',
      eventSaid,
      signerAid: receipt.signerAid,
      signature: receipt.signature,
    });
  }

  async getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>> {
    const docs = await this.receipts.find({ eventSaid }) as ReceiptDoc[];
    return docs.map(({ signerAid, signature }) => ({ signerAid, signature }));
  }

  // ── Registries ──

  async putRegistry(name: string, data: { said: string; name: string; lastSaid: string; lastSn: number }): Promise<void> {
    await this.registries.update(
      { name },
      { _collection: 'registry', name, said: data.said, lastSaid: data.lastSaid, lastSn: data.lastSn } satisfies RegistryDoc,
      { upsert: true },
    );
  }

  async getRegistry(name: string): Promise<{ said: string; name: string; lastSaid: string; lastSn: number } | null> {
    const doc = await this.registries.findOne({ name }) as RegistryDoc | null;
    return doc ? { said: doc.said, name: doc.name, lastSaid: doc.lastSaid, lastSn: doc.lastSn } : null;
  }

  async listRegistries(): Promise<Array<{ said: string; name: string }>> {
    const docs = await this.registries.find({}) as RegistryDoc[];
    return docs.map(({ said, name }) => ({ said, name }));
  }

  // ── Credentials ──

  async putCredential(said: string, data: { said: string; registrySaid: string; state: string; raw: string }): Promise<void> {
    await this.credentials.update(
      { said },
      { _collection: 'credential', said, registrySaid: data.registrySaid, state: data.state, raw: data.raw } satisfies CredentialDoc,
      { upsert: true },
    );
  }

  async getCredential(said: string): Promise<{ said: string; registrySaid: string; state: string; raw: string } | null> {
    const doc = await this.credentials.findOne({ said }) as CredentialDoc | null;
    return doc ? { said: doc.said, registrySaid: doc.registrySaid, state: doc.state, raw: doc.raw } : null;
  }

  async listCredentials(): Promise<Array<{ said: string; state: string }>> {
    const docs = await this.credentials.find({}) as CredentialDoc[];
    return docs.map(({ said, state }) => ({ said, state }));
  }

  // ── Endpoints ──

  async putEndpoint(aid: string, url: string): Promise<void> {
    await this.endpoints.update(
      { aid },
      { _collection: 'endpoint', aid, url } satisfies EndpointDoc,
      { upsert: true },
    );
  }

  async getEndpoint(aid: string): Promise<string | null> {
    const doc = await this.endpoints.findOne({ aid }) as EndpointDoc | null;
    return doc ? doc.url : null;
  }

  // ── Witness Identity ──

  async putWitnessIdentity(signerQb64: string, prefix: string): Promise<void> {
    await this.identity.update(
      { _tag: 'witness-identity' },
      { _collection: 'witnessIdentity', _tag: 'witness-identity', signerQb64, prefix } satisfies IdentityDoc,
      { upsert: true },
    );
  }

  async getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null> {
    const doc = await this.identity.findOne({ _tag: 'witness-identity' }) as IdentityDoc | null;
    return doc ? { signerQb64: doc.signerQb64, prefix: doc.prefix } : null;
  }

  // ── Lifecycle ──

  async close(): Promise<void> {
    // nedb-promises doesn't have an explicit close; no-op for interface compliance
  }
}
