import type {
  IEscrowStore,
  EscrowEntry,
  SealInfo,
} from "../interfaces/IEscrowStore.js";
import type { EscrowReason } from "../types/EscrowReason.js";

/** In-memory reference implementation of IEscrowStore. */
export class MemoryEscrowStore implements IEscrowStore {
  private escrows = new Map<string, EscrowEntry[]>();
  private sources = new Map<string, SealInfo>();

  private escrowKey(escrowType: EscrowReason): string {
    return escrowType;
  }

  private sourceKey(prefix: string, said: string): string {
    return `${prefix}:${said}`;
  }

  async add(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<void> {
    const key = this.escrowKey(escrowType);
    const entries = this.escrows.get(key) ?? [];
    if (!entries.some((e) => e.prefix === prefix && e.sn === sn && e.said === said)) {
      entries.push({ prefix, sn, said });
    }
    this.escrows.set(key, entries);
  }

  async remove(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<void> {
    const key = this.escrowKey(escrowType);
    const entries = this.escrows.get(key) ?? [];
    this.escrows.set(
      key,
      entries.filter(
        (e) => !(e.prefix === prefix && e.sn === sn && e.said === said),
      ),
    );
  }

  async *iterate(escrowType: EscrowReason): AsyncIterable<EscrowEntry> {
    const entries = this.escrows.get(this.escrowKey(escrowType)) ?? [];
    for (const entry of [...entries]) {
      yield entry;
    }
  }

  async getByPrefix(
    escrowType: EscrowReason,
    prefix: string,
  ): Promise<EscrowEntry[]> {
    const entries = this.escrows.get(this.escrowKey(escrowType)) ?? [];
    return entries.filter((e) => e.prefix === prefix);
  }

  async has(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<boolean> {
    const entries = this.escrows.get(this.escrowKey(escrowType)) ?? [];
    return entries.some(
      (e) => e.prefix === prefix && e.sn === sn && e.said === said,
    );
  }

  async putSource(prefix: string, said: string, sealInfo: SealInfo): Promise<void> {
    this.sources.set(this.sourceKey(prefix, said), sealInfo);
  }

  async getSource(prefix: string, said: string): Promise<SealInfo | undefined> {
    return this.sources.get(this.sourceKey(prefix, said));
  }
}
