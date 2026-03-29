/**
 * MemoryStore — simple in-memory + JSON-file persistence for the kerizon CLI.
 *
 * Stores KEL events, key state (Kever snapshots), signing keys (Signer qb64),
 * and alias-to-prefix mappings. Serializes/deserializes to a JSON file for
 * cross-process persistence between CLI invocations.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { Serder } from '@kerizon/cesr';
import { Kever } from '@kerizon/keri-core';

// ── Serialized shapes ─────────────────────────────────────────────

interface SerializedEvent {
  raw: number[];     // Serder.raw as number array (JSON-safe)
  sigs: string[];    // qb64 signatures
}

interface SerializedKever {
  prefix: string;
  sn: number;
  currentKeys: string[];
  signingThreshold: string;
  nextDigests: string[];
  nextThreshold: string;
  witnesses: string[];
  witnessThreshold: number;
  configTraits: string[];
  transferable: boolean;
  lastEstSn: number;
  lastEstSaid: string;
  delegator?: string;
}

interface SerializedIdentity {
  alias: string;
  prefix: string;
  currentSignerQb64s: string[];
  nextSignerQb64s: string[];
}

export interface SerializedRegistry {
  said: string;
  name: string;
  events: string[];  // serialized TEL event SAIDs
}

export interface SerializedCredential {
  said: string;
  registrySaid: string;
  state: string;
  raw: string;  // JSON string of the ACDC
}

interface StoreData {
  events: Record<string, SerializedEvent[]>;   // prefix → events
  kevers: Record<string, SerializedKever>;     // prefix → kever snapshot
  aliases: Record<string, string>;             // alias → prefix
  identities: Record<string, SerializedIdentity>; // prefix → signing keys
  registries: Record<string, SerializedRegistry>;  // registry name → metadata
  credentials: Record<string, SerializedCredential>; // credential SAID → data
}

// ── Store interface ───────────────────────────────────────────────

export interface Store {
  appendEvent(prefix: string, serder: Serder, sigs: string[]): void;
  getEvents(prefix: string): Array<{ serder: Serder; sigs: string[] }>;

  getKever(prefix: string): Kever | undefined;
  putKever(prefix: string, kever: Kever): void;

  setAlias(alias: string, prefix: string): void;
  getPrefix(alias: string): string | undefined;
  listAliases(): Array<{ name: string; prefix: string }>;

  setSigners(prefix: string, alias: string, currentQb64s: string[], nextQb64s: string[]): void;
  getIdentity(prefix: string): SerializedIdentity | undefined;

  putRegistry(name: string, registry: SerializedRegistry): void;
  getRegistry(name: string): SerializedRegistry | undefined;
  listRegistries(): SerializedRegistry[];

  putCredential(said: string, credential: SerializedCredential): void;
  getCredential(said: string): SerializedCredential | undefined;
  listCredentials(): SerializedCredential[];

  save(path: string): void;
}

// ── Implementation ────────────────────────────────────────────────

export class MemoryStore implements Store {
  private events: Map<string, SerializedEvent[]> = new Map();
  private kevers: Map<string, SerializedKever> = new Map();
  private aliases: Map<string, string> = new Map();
  private identities: Map<string, SerializedIdentity> = new Map();
  private registries: Map<string, SerializedRegistry> = new Map();
  private credentials: Map<string, SerializedCredential> = new Map();

  appendEvent(prefix: string, serder: Serder, sigs: string[]): void {
    if (!this.events.has(prefix)) {
      this.events.set(prefix, []);
    }
    this.events.get(prefix)!.push({
      raw: Array.from(serder.raw),
      sigs,
    });
  }

  getEvents(prefix: string): Array<{ serder: Serder; sigs: string[] }> {
    const serialized = this.events.get(prefix) ?? [];
    return serialized.map(e => ({
      serder: Serder.fromRaw(new Uint8Array(e.raw)),
      sigs: e.sigs,
    }));
  }

  getKever(prefix: string): Kever | undefined {
    const sk = this.kevers.get(prefix);
    if (!sk) return undefined;
    // Reconstruct by creating a synthetic inception Serder and applying events.
    // However, Kever's constructor is private — we need to go through fromInception
    // or applyEstablishment. We'll rebuild from the event log.
    return this._rebuildKever(prefix);
  }

  putKever(prefix: string, kever: Kever): void {
    this.kevers.set(prefix, {
      prefix: kever.prefix,
      sn: kever.sn,
      currentKeys: kever.currentKeys,
      signingThreshold: kever.signingThreshold,
      nextDigests: kever.nextDigests,
      nextThreshold: kever.nextThreshold,
      witnesses: kever.witnesses,
      witnessThreshold: kever.witnessThreshold,
      configTraits: kever.configTraits,
      transferable: kever.transferable,
      lastEstSn: kever.lastEstSn,
      lastEstSaid: kever.lastEstSaid,
      delegator: kever.delegator,
    });
  }

  setAlias(alias: string, prefix: string): void {
    this.aliases.set(alias, prefix);
  }

  getPrefix(alias: string): string | undefined {
    return this.aliases.get(alias);
  }

  listAliases(): Array<{ name: string; prefix: string }> {
    const result: Array<{ name: string; prefix: string }> = [];
    for (const [name, prefix] of this.aliases) {
      result.push({ name, prefix });
    }
    return result;
  }

  setSigners(prefix: string, alias: string, currentQb64s: string[], nextQb64s: string[]): void {
    this.identities.set(prefix, {
      alias,
      prefix,
      currentSignerQb64s: currentQb64s,
      nextSignerQb64s: nextQb64s,
    });
  }

  getIdentity(prefix: string): SerializedIdentity | undefined {
    return this.identities.get(prefix);
  }

  putRegistry(name: string, registry: SerializedRegistry): void {
    this.registries.set(name, registry);
  }

  getRegistry(name: string): SerializedRegistry | undefined {
    return this.registries.get(name);
  }

  listRegistries(): SerializedRegistry[] {
    return Array.from(this.registries.values());
  }

  putCredential(said: string, credential: SerializedCredential): void {
    this.credentials.set(said, credential);
  }

  getCredential(said: string): SerializedCredential | undefined {
    return this.credentials.get(said);
  }

  listCredentials(): SerializedCredential[] {
    return Array.from(this.credentials.values());
  }

  save(path: string): void {
    const dir = dirname(path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const data: StoreData = {
      events: Object.fromEntries(this.events),
      kevers: Object.fromEntries(this.kevers),
      aliases: Object.fromEntries(this.aliases),
      identities: Object.fromEntries(this.identities),
      registries: Object.fromEntries(this.registries),
      credentials: Object.fromEntries(this.credentials),
    };
    writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8');
  }

  static load(path: string): MemoryStore {
    const store = new MemoryStore();
    if (!existsSync(path)) return store;

    const raw = readFileSync(path, 'utf-8');
    const data: StoreData = JSON.parse(raw);

    for (const [k, v] of Object.entries(data.events)) {
      store.events.set(k, v);
    }
    for (const [k, v] of Object.entries(data.kevers)) {
      store.kevers.set(k, v);
    }
    for (const [k, v] of Object.entries(data.aliases)) {
      store.aliases.set(k, v);
    }
    for (const [k, v] of Object.entries(data.identities ?? {})) {
      store.identities.set(k, v);
    }
    for (const [k, v] of Object.entries(data.registries ?? {})) {
      store.registries.set(k, v);
    }
    for (const [k, v] of Object.entries(data.credentials ?? {})) {
      store.credentials.set(k, v);
    }

    return store;
  }

  /**
   * Rebuild a Kever from the stored event log.
   * This is the canonical way to recover key state since Kever's constructor
   * is private and only accessible through fromInception/apply* methods.
   */
  private _rebuildKever(prefix: string): Kever | undefined {
    const events = this.getEvents(prefix);
    if (events.length === 0) return undefined;

    let kever = Kever.fromInception(events[0].serder);
    for (let i = 1; i < events.length; i++) {
      const serder = events[i].serder;
      const ilk = serder.ilk;
      if (ilk === 'rot' || ilk === 'drt') {
        kever = kever.applyEstablishment(serder);
      } else if (ilk === 'ixn') {
        kever = kever.applyInteraction(serder);
      }
    }
    return kever;
  }
}
