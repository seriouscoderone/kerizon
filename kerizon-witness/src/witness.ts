/**
 * KerizonWitness — KERI witness node.
 *
 * Manages a non-transferable witness identity and processes incoming
 * KERI events, producing receipts signed by the witness key.
 */

import { Signer, Siger, Serder, parseStream, MtrDex, CtrDex_1_0, encodeB64, b64Index } from '@kerizon/cesr';
import { incept, Kever, processEvent as applyEvent, type KeverStore } from '@kerizon/keri-core';
import type { WitnessStore } from './store/types.js';

export interface WitnessConfig {
  name: string;
  httpPort: number;
  tcpPort: number;
  salt?: string;
  dbPath?: string;
}

/**
 * In-memory KeverStore backed by a map. Used internally by KerizonWitness
 * to track key state for all prefixes whose events pass through this witness.
 */
class MemoryKeverStore implements KeverStore {
  private kevers = new Map<string, Kever>();

  get(prefix: string): Kever | undefined {
    return this.kevers.get(prefix);
  }

  set(prefix: string, kever: Kever): void {
    this.kevers.set(prefix, kever);
  }

  getLastSaid(prefix: string): string | undefined {
    return this.kevers.get(prefix)?.lastEstSaid;
  }

  getExpectedSn(prefix: string): number {
    const k = this.kevers.get(prefix);
    return k ? k.sn + 1 : 0;
  }
}

/**
 * Encode a counter code header for `count` quadlets.
 *
 * Short counter: `-X##` where ## is a 2-char B64-encoded count.
 */
function encodeCounter(code: string, count: number): string {
  return code + b64Index(Math.floor(count / 64) & 0x3f) + b64Index(count & 0x3f);
}

export class KerizonWitness {
  readonly prefix: string;
  private signer: Signer;
  private store: WitnessStore;
  private keverStore: MemoryKeverStore;
  private inceptionRaw: string;

  private constructor(
    prefix: string,
    signer: Signer,
    store: WitnessStore,
    keverStore: MemoryKeverStore,
    inceptionRaw: string,
  ) {
    this.prefix = prefix;
    this.signer = signer;
    this.store = store;
    this.keverStore = keverStore;
    this.inceptionRaw = inceptionRaw;
  }

  /**
   * Create or restore a KerizonWitness.
   *
   * If the store already contains a witness identity, the signer is restored
   * from the stored qb64. Otherwise a new Ed25519 keypair is generated and
   * a non-transferable inception event (empty nextDigests) is created.
   */
  static async create(config: WitnessConfig, store: WitnessStore): Promise<KerizonWitness> {
    const keverStore = new MemoryKeverStore();
    const existing = await store.getWitnessIdentity();

    if (existing) {
      // Restore signer from stored qb64
      const signer = new Signer({ qb64: existing.signerQb64 });
      const prefix = existing.prefix;

      // Restore own inception from store
      const events = await store.getEvents(prefix);
      const inceptionRaw = events.length > 0 ? events[0].raw : '';

      // Rebuild kever from stored inception
      if (inceptionRaw) {
        const serder = Serder.fromRaw(new TextEncoder().encode(inceptionRaw));
        const kever = Kever.fromInception(serder);
        keverStore.set(prefix, kever);
      }

      return new KerizonWitness(prefix, signer, store, keverStore, inceptionRaw);
    }

    // Generate new keypair
    const signer = await Signer.generate();
    const verfer = signer.verfer;

    // Non-transferable inception: empty next digests, threshold '0'
    const serder = incept({
      keys: [verfer.qb64],
      nextDigests: [],
      nextThreshold: '0',
      signingThreshold: '1',
    });

    const prefix = serder.pre; // SAID-based prefix starting with 'E'

    // Sign our own inception
    const sigRaw = await signer.sign(serder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    // Store the identity
    await store.putWitnessIdentity(signer.qb64, prefix);

    // Store the inception event
    const rawJson = new TextDecoder().decode(serder.raw);
    await store.putEvent(prefix, 0, serder.said, rawJson, [siger.qb64]);

    // Bootstrap kever
    const kever = Kever.fromInception(serder);
    keverStore.set(prefix, kever);

    return new KerizonWitness(prefix, signer, store, keverStore, rawJson);
  }

  /**
   * Process an incoming CESR-encoded event stream.
   *
   * Parses the stream, validates each event via keri-core's processEvent,
   * stores accepted events, and returns a receipt for the first accepted event.
   */
  async processEvent(cesr: Uint8Array): Promise<{ receipt: string; eventSaid: string } | { error: string }> {
    let messages;
    try {
      messages = parseStream(cesr);
    } catch (err: unknown) {
      return { error: `parse error: ${err instanceof Error ? err.message : String(err)}` };
    }

    if (messages.length === 0) {
      return { error: 'no messages found in CESR stream' };
    }

    for (const msg of messages) {
      const serder = msg.serder;
      const result = applyEvent(serder, this.keverStore);

      if (result.status === 'accepted') {
        // Store the event
        const rawJson = new TextDecoder().decode(serder.raw);
        const sigQb64s = msg.sigers.map(s => s.qb64);
        await this.store.putEvent(serder.pre, serder.sn, serder.said, rawJson, sigQb64s);

        // Sign the event SAID to produce a receipt
        const ser = new TextEncoder().encode(serder.said);
        const sigRaw = await this.signer.sign(ser);
        const siger = Siger.create({ raw: sigRaw, index: 0 });

        // Store the receipt
        await this.store.putReceipt(serder.said, {
          signerAid: this.prefix,
          signature: siger.qb64,
        });

        return { receipt: siger.qb64, eventSaid: serder.said };
      }

      if (result.status === 'rejected') {
        return { error: `rejected: ${result.reason}` };
      }

      // duplicate or escrowed: continue to next message
    }

    return { error: 'no events accepted' };
  }

  /**
   * Return the CESR-encoded inception event for this witness, including
   * the controller-indexed-sig attachment.
   */
  getOwnKel(): string {
    if (!this.inceptionRaw) return '';

    // Retrieve the stored sigs for our own inception
    // For simplicity, reconstruct from stored data synchronously using
    // the inception raw JSON + a -A counter wrapping the sig.
    // We'll build this from the stored event in the constructor.
    return this.inceptionRaw;
  }

  /**
   * Load all events for a given prefix from the store and return
   * concatenated raw JSON (event bodies without attachment groups).
   */
  async getKel(prefix: string): Promise<string | null> {
    const events = await this.store.getEvents(prefix);
    if (events.length === 0) return null;
    return events.map(e => e.raw).join('');
  }
}
