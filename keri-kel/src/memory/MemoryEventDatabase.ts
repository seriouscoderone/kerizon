import type { IEventDatabase } from "../interfaces/IEventDatabase.js";
import type { KeyStateRecord } from "../types/KeyStateRecord.js";

/** In-memory reference implementation of IEventDatabase. */
export class MemoryEventDatabase implements IEventDatabase {
  private events = new Map<string, Uint8Array>();
  private kel = new Map<string, string[]>();
  private fel = new Map<string, string[]>();
  private sigs = new Map<
    string,
    Array<{ index: number; raw: Uint8Array; qb64: string }>
  >();
  private wigs = new Map<
    string,
    Array<{ index: number; raw: Uint8Array; qb64: string }>
  >();
  private datetimes = new Map<string, string>();
  private states = new Map<string, KeyStateRecord>();
  private fns = new Map<string, number>();
  private fnCounters = new Map<string, number>();

  private key(prefix: string, id: string): string {
    return `${prefix}:${id}`;
  }

  private kelKey(prefix: string, sn: number): string {
    return `${prefix}:${sn}`;
  }

  async putEvent(prefix: string, said: string, event: Uint8Array): Promise<void> {
    this.events.set(this.key(prefix, said), event);
  }

  async getEvent(prefix: string, said: string): Promise<Uint8Array | undefined> {
    return this.events.get(this.key(prefix, said));
  }

  async addKelEntry(prefix: string, sn: number, said: string): Promise<void> {
    const k = this.kelKey(prefix, sn);
    const existing = this.kel.get(k) ?? [];
    if (!existing.includes(said)) {
      existing.push(said);
    }
    this.kel.set(k, existing);
  }

  async getKelEntry(prefix: string, sn: number): Promise<string[]> {
    return this.kel.get(this.kelKey(prefix, sn)) ?? [];
  }

  async appendFel(prefix: string, said: string): Promise<number> {
    const counter = this.fnCounters.get(prefix) ?? 0;
    const fn = counter;
    this.fnCounters.set(prefix, counter + 1);
    const list = this.fel.get(prefix) ?? [];
    list.push(said);
    this.fel.set(prefix, list);
    return fn;
  }

  async getFelEntry(prefix: string, fn: number): Promise<string | undefined> {
    const list = this.fel.get(prefix);
    return list?.[fn];
  }

  async putSigs(
    prefix: string,
    said: string,
    sigers: Array<{ index: number; raw: Uint8Array; qb64: string }>,
  ): Promise<void> {
    const k = this.key(prefix, said);
    const existing = this.sigs.get(k) ?? [];
    for (const siger of sigers) {
      if (!existing.some((s) => s.qb64 === siger.qb64)) {
        existing.push(siger);
      }
    }
    this.sigs.set(k, existing);
  }

  async getSigs(
    prefix: string,
    said: string,
  ): Promise<Array<{ index: number; raw: Uint8Array; qb64: string }>> {
    return this.sigs.get(this.key(prefix, said)) ?? [];
  }

  async putWigs(
    prefix: string,
    said: string,
    wigers: Array<{ index: number; raw: Uint8Array; qb64: string }>,
  ): Promise<void> {
    const k = this.key(prefix, said);
    const existing = this.wigs.get(k) ?? [];
    for (const wiger of wigers) {
      if (!existing.some((w) => w.qb64 === wiger.qb64)) {
        existing.push(wiger);
      }
    }
    this.wigs.set(k, existing);
  }

  async getWigs(
    prefix: string,
    said: string,
  ): Promise<Array<{ index: number; raw: Uint8Array; qb64: string }>> {
    return this.wigs.get(this.key(prefix, said)) ?? [];
  }

  async putDatetime(prefix: string, said: string, datetime: string): Promise<void> {
    const k = this.key(prefix, said);
    if (!this.datetimes.has(k)) {
      this.datetimes.set(k, datetime);
    }
  }

  async getDatetime(prefix: string, said: string): Promise<string | undefined> {
    return this.datetimes.get(this.key(prefix, said));
  }

  async putState(prefix: string, state: KeyStateRecord): Promise<void> {
    this.states.set(prefix, state);
  }

  async getState(prefix: string): Promise<KeyStateRecord | undefined> {
    return this.states.get(prefix);
  }

  async putFn(prefix: string, said: string, fn: number): Promise<void> {
    this.fns.set(this.key(prefix, said), fn);
  }

  async getFn(prefix: string, said: string): Promise<number | undefined> {
    return this.fns.get(this.key(prefix, said));
  }
}
