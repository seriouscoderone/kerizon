/**
 * MemoryPersistence — in-memory implementation of PersistencePort.
 *
 * All data lives in plain Maps; nothing is written to disk. Useful for
 * tests and short-lived processes that don't need durable storage.
 */

import type { PersistencePort, SerializedKeyState } from './types.js';

export class MemoryPersistence implements PersistencePort {
  private events = new Map<string, Array<{ sn: number; said: string; raw: string; sigs: string[] }>>();
  private keyStates = new Map<string, SerializedKeyState>();
  private aliases = new Map<string, string>(); // alias -> prefix
  private signers = new Map<string, { alias: string; currentQb64s: string[]; nextQb64s: string[] }>();
  private receipts = new Map<string, Array<{ signerAid: string; signature: string }>>();
  private registries = new Map<string, { said: string; name: string; lastSaid: string; lastSn: number }>();
  private credentials = new Map<string, { said: string; registrySaid: string; state: string; raw: string }>();
  private endpoints = new Map<string, string>();
  private witnessIdentity: { signerQb64: string; prefix: string } | null = null;

  // ── KEL Events ──

  async putEvent(prefix: string, sn: number, said: string, raw: string, sigs: string[]): Promise<void> {
    if (!this.events.has(prefix)) {
      this.events.set(prefix, []);
    }
    this.events.get(prefix)!.push({ sn, said, raw, sigs });
  }

  async getEvents(prefix: string): Promise<Array<{ sn: number; said: string; raw: string; sigs: string[] }>> {
    const evts = this.events.get(prefix) ?? [];
    return evts.slice().sort((a, b) => a.sn - b.sn);
  }

  async getEvent(prefix: string, sn: number): Promise<{ said: string; raw: string; sigs: string[] } | null> {
    const evts = this.events.get(prefix);
    if (!evts) return null;
    const found = evts.find(e => e.sn === sn);
    return found ? { said: found.said, raw: found.raw, sigs: found.sigs } : null;
  }

  // ── Key State ──

  async putKeyState(prefix: string, state: SerializedKeyState): Promise<void> {
    this.keyStates.set(prefix, state);
  }

  async getKeyState(prefix: string): Promise<SerializedKeyState | null> {
    return this.keyStates.get(prefix) ?? null;
  }

  // ── Aliases ──

  async putAlias(alias: string, prefix: string): Promise<void> {
    this.aliases.set(alias, prefix);
  }

  async getPrefix(alias: string): Promise<string | null> {
    return this.aliases.get(alias) ?? null;
  }

  async listAliases(): Promise<Array<{ alias: string; prefix: string }>> {
    const result: Array<{ alias: string; prefix: string }> = [];
    for (const [alias, prefix] of this.aliases) {
      result.push({ alias, prefix });
    }
    return result;
  }

  // ── Signing Keys ──

  async putSigners(prefix: string, data: { alias: string; currentQb64s: string[]; nextQb64s: string[] }): Promise<void> {
    this.signers.set(prefix, data);
  }

  async getSigners(prefix: string): Promise<{ alias: string; currentQb64s: string[]; nextQb64s: string[] } | null> {
    return this.signers.get(prefix) ?? null;
  }

  // ── Receipts ──

  async putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void> {
    if (!this.receipts.has(eventSaid)) {
      this.receipts.set(eventSaid, []);
    }
    this.receipts.get(eventSaid)!.push(receipt);
  }

  async getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>> {
    return this.receipts.get(eventSaid) ?? [];
  }

  // ── Registries ──

  async putRegistry(name: string, data: { said: string; name: string; lastSaid: string; lastSn: number }): Promise<void> {
    this.registries.set(name, data);
  }

  async getRegistry(name: string): Promise<{ said: string; name: string; lastSaid: string; lastSn: number } | null> {
    return this.registries.get(name) ?? null;
  }

  async listRegistries(): Promise<Array<{ said: string; name: string }>> {
    return Array.from(this.registries.values()).map(({ said, name }) => ({ said, name }));
  }

  // ── Credentials ──

  async putCredential(said: string, data: { said: string; registrySaid: string; state: string; raw: string }): Promise<void> {
    this.credentials.set(said, data);
  }

  async getCredential(said: string): Promise<{ said: string; registrySaid: string; state: string; raw: string } | null> {
    return this.credentials.get(said) ?? null;
  }

  async listCredentials(): Promise<Array<{ said: string; state: string }>> {
    return Array.from(this.credentials.values()).map(({ said, state }) => ({ said, state }));
  }

  // ── Endpoints ──

  async putEndpoint(aid: string, url: string): Promise<void> {
    this.endpoints.set(aid, url);
  }

  async getEndpoint(aid: string): Promise<string | null> {
    return this.endpoints.get(aid) ?? null;
  }

  // ── Witness Identity ──

  async putWitnessIdentity(signerQb64: string, prefix: string): Promise<void> {
    this.witnessIdentity = { signerQb64, prefix };
  }

  async getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null> {
    return this.witnessIdentity;
  }

  // ── Lifecycle ──

  async close(): Promise<void> {
    // No-op for in-memory store
  }
}
