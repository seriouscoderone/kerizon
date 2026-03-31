/**
 * KerizonWitness — KERI witness node.
 *
 * Manages a non-transferable witness identity and processes incoming
 * KERI events, producing receipts signed by the witness key.
 */

import { Signer, Siger, Serder, parseStream, MtrDex, CtrDex_1_0, encodeB64, b64Index, Matter, Diger, makeVersionString } from '@kerizon/cesr';
import { incept, Kever, processEvent as applyEvent, reply, type KeverStore } from '@kerizon/keri-core';
import type { WitnessStore } from './store/types.js';
import type { WitnessHandler } from './ports.js';

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

/**
 * Build an inception Serder for a non-transferable basic-prefix identifier.
 *
 * Unlike `Serder.fromKed()` which always sets `i = d` (SAID) for inception,
 * this keeps `i` as the provided basic prefix (B-code verfer qb64) and only
 * computes `d` as a SAID over the serialized KED.
 *
 * The algorithm iterates to converge on the correct version-string size and SAID:
 * 1. Build KED with placeholder `d`, correct `i`, and a guess at the version string
 * 2. Hash to get SAID for `d`
 * 3. Fix the version string size with the actual serialized length
 * 4. Re-hash with the corrected size to get the final stable SAID
 */
function buildBasicInception(prefix: string, keyQb64: string): Serder {
  const saidCode = MtrDex.Blake3_256; // 'E'
  const placeholderLen = 44; // Blake3-256 qb64 full size
  const dummy = '#'.repeat(placeholderLen);

  // Canonical field order matching ICP_FIELDS
  const ked: Record<string, unknown> = {
    v: '',
    t: 'icp',
    d: '',
    i: prefix,
    s: '0',
    kt: '1',
    k: [keyQb64],
    nt: '0',
    n: [],
    bt: '0',
    b: [],
    c: [],
    a: [],
  };

  // Iterate to converge on stable SAID + size (3 passes)
  for (let pass = 0; pass < 3; pass++) {
    const currentSize = pass === 0
      ? 0
      : new TextEncoder().encode(JSON.stringify(ked)).length;

    ked['v'] = makeVersionString({
      protocol: 'KERI',
      major: 1,
      minor: 0,
      kind: 'JSON',
      size: currentSize,
    });

    // Replace only d with dummy (NOT i -- i stays as the basic prefix)
    const template = { ...ked, d: dummy };
    const ser = new TextEncoder().encode(JSON.stringify(template));
    const said = Diger.digest(ser, saidCode).qb64;
    ked['d'] = said;
  }

  // Final size fix
  const serialized = JSON.stringify(ked);
  const raw = new TextEncoder().encode(serialized);
  const actualSize = raw.length;

  // Check if size in version string matches
  const sizeInVs = parseInt((ked['v'] as string).slice(10, 16), 16);
  if (sizeInVs !== actualSize) {
    ked['v'] = makeVersionString({
      protocol: 'KERI',
      major: 1,
      minor: 0,
      kind: 'JSON',
      size: actualSize,
    });
    // Re-hash with final version string
    const template = { ...ked, d: dummy };
    const ser = new TextEncoder().encode(JSON.stringify(template));
    ked['d'] = Diger.digest(ser, saidCode).qb64;
  }

  const finalRaw = new TextEncoder().encode(JSON.stringify(ked));
  return Serder.fromRaw(finalRaw);
}

export class KerizonWitness {
  readonly prefix: string;
  private signer: Signer;
  private store: WitnessStore;
  private keverStore: MemoryKeverStore;
  private inceptionRaw: string;
  private inceptionSig: string;
  private httpPort: number;

  private constructor(
    prefix: string,
    signer: Signer,
    store: WitnessStore,
    keverStore: MemoryKeverStore,
    inceptionRaw: string,
    inceptionSig: string,
    httpPort: number,
  ) {
    this.prefix = prefix;
    this.signer = signer;
    this.store = store;
    this.keverStore = keverStore;
    this.inceptionRaw = inceptionRaw;
    this.inceptionSig = inceptionSig;
    this.httpPort = httpPort;
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
      const inceptionSig = events.length > 0 && events[0].sigs.length > 0
        ? events[0].sigs[0]
        : '';

      // Rebuild kever from stored inception
      if (inceptionRaw) {
        const serder = Serder.fromRaw(new TextEncoder().encode(inceptionRaw));
        const kever = Kever.fromInception(serder);
        keverStore.set(prefix, kever);
      }

      return new KerizonWitness(prefix, signer, store, keverStore, inceptionRaw, inceptionSig, config.httpPort);
    }

    // Generate new keypair
    const signer = await Signer.generate();

    // Create B-prefix (non-transferable Ed25519) for the witness.
    // KERI requires non-transferable witnesses to use a basic prefix where
    // the AID IS the public key (code 'B'), not a SAID-based prefix ('E').
    const ntVerfer = new Matter({ code: MtrDex.Ed25519N, raw: signer.verfer.raw });
    const prefix = ntVerfer.qb64; // 'B...' — 44-char basic prefix

    // Build inception KED with i = basic prefix (not SAID).
    // Serder.fromKed() cannot be used here because Saider.saidify() forces
    // i = d for inception types. We compute the SAID for d only, keeping i
    // as the basic prefix.
    const serder = buildBasicInception(prefix, ntVerfer.qb64);

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

    return new KerizonWitness(prefix, signer, store, keverStore, rawJson, siger.qb64, config.httpPort);
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
      const result = await applyEvent(serder, this.keverStore);

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
   *
   * kli's OOBI resolver expects a full CESR message: JSON body followed by
   * a `-AAB` (ControllerIdxSigs, 1 sig = 22 quadlets) counter + the signature.
   */
  getOwnKel(): string {
    if (!this.inceptionRaw || !this.inceptionSig) return '';

    // Each Ed25519 indexed sig is 88 chars = 22 quadlets
    const sigQuadlets = this.inceptionSig.length / 4;
    const counter = encodeCounter(CtrDex_1_0.ControllerIdxSigs, sigQuadlets);
    return this.inceptionRaw + counter + this.inceptionSig;
  }

  /**
   * Return the full OOBI response: inception event with sig attachment,
   * followed by a `/loc/scheme` reply message declaring this witness's
   * HTTP endpoint, signed with a non-transferable receipt couple (`-C`).
   *
   * kli's OOBI resolver expects reply messages so it can store the
   * witness's endpoint location for future communication.
   */
  async getOobiResponse(): Promise<string> {
    const kel = this.getOwnKel();
    if (!kel) return '';

    // Build a /loc/scheme reply declaring our HTTP endpoint
    const locSerder = reply({
      route: '/loc/scheme',
      data: {
        eid: this.prefix,
        scheme: 'http',
        url: `http://127.0.0.1:${this.httpPort}`,
      },
    });

    // Sign the reply with an unindexed Ed25519 signature (Cigar / code 0B)
    const sigRaw = await this.signer.sign(locSerder.raw);
    const cigar = new Matter({ code: MtrDex.Ed25519_Sig, raw: sigRaw });

    // Non-transferable receipt couple: prefix (44 chars) + cigar (88 chars) = 132 chars = 33 quadlets
    const coupleQuadlets = (this.prefix.length + cigar.qb64.length) / 4;
    const counter = encodeCounter(CtrDex_1_0.NonTransReceiptCouples, coupleQuadlets);

    return kel + new TextDecoder().decode(locSerder.raw) + counter + this.prefix + cigar.qb64;
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

  /** Create a WitnessHandler for use with transport adapters. */
  createHandler(): WitnessHandler {
    return {
      handleEventSubmission: async (cesr) => {
        const result = await this.processEvent(cesr);
        if ('receipt' in result) {
          return { status: 204 };
        }
        return { status: 400, body: result.error };
      },

      handleOobiRequest: async (_path) => {
        const body = await this.getOobiResponse();
        return {
          status: 200,
          contentType: 'application/json+cesr',
          headers: { 'KERI-AID': this.prefix },
          body,
        };
      },

      handleKelQuery: async (prefix) => {
        const kel = await this.getKel(prefix);
        if (kel) {
          return { status: 200, body: kel };
        }
        return { status: 404 };
      },
    };
  }
}
