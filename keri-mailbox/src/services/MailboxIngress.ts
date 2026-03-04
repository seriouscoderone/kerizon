import type { IMailboxStore } from "../interfaces/IMailboxStore.js";
import type { IKeyStateResolver } from "../interfaces/IKeyStateResolver.js";
import type { SubmitParams, SubmitResult } from "../types/results.js";
import type { TopicAddress } from "../types/TopicAddress.js";
import { parseSad } from "../core/SadParser.js";
import { parseAttachments } from "../core/AttachmentParser.js";
import { evaluateThreshold } from "../core/ThresholdEvaluator.js";

export interface MailboxIngressOptions {
  store: IMailboxStore;
  resolver: IKeyStateResolver;
  /**
   * If true, every submit must include CESR attachments that satisfy the
   * sender's current key state threshold. Defaults to false.
   */
  requireSenderAuth?: boolean;
}

/**
 * Handles inbound /fwd message submission.
 *
 * Optionally authenticates senders by verifying CESR attachment signatures
 * against the sender's key state. Delegates storage to the injected IMailboxStore.
 */
export class MailboxIngress {
  private readonly store: IMailboxStore;
  private readonly resolver: IKeyStateResolver;
  private readonly requireSenderAuth: boolean;

  constructor(opts: MailboxIngressOptions) {
    this.store = opts.store;
    this.resolver = opts.resolver;
    this.requireSenderAuth = opts.requireSenderAuth ?? false;
  }

  /**
   * Submit a message payload to a recipient's mailbox topic.
   *
   * Throws if:
   *   - The recipient is not provisioned.
   *   - requireSenderAuth is true and no valid attachments are provided.
   *   - requireSenderAuth is true and signature verification fails.
   */
  async submit(params: SubmitParams): Promise<SubmitResult> {
    const { sender, recipient, topic, payload, attachments: attachmentBytes } =
      params;

    const isProvisioned = await this.store.isProvisioned(recipient);
    if (!isProvisioned) {
      throw new Error(`Recipient ${recipient} is not provisioned`);
    }

    if (this.requireSenderAuth) {
      if (!attachmentBytes || attachmentBytes.length === 0) {
        throw new Error(
          "Sender authentication required but no attachments provided",
        );
      }

      const keyState = await this.resolver.resolve(sender);
      if (!keyState) {
        throw new Error(`Cannot resolve key state for sender ${sender}`);
      }

      const combined = new Uint8Array(payload.length + attachmentBytes.length);
      combined.set(payload);
      combined.set(attachmentBytes, payload.length);

      let parsed;
      try {
        parsed = parseSad(combined);
      } catch (e) {
        throw new Error(`Failed to parse CESR message: ${e}`);
      }

      const sigs = parseAttachments(parsed.attachments);
      const valid = await evaluateThreshold({
        indexedSigs: sigs.indexedSigs,
        coupledSigs: sigs.coupledSigs,
        message: parsed.raw,
        keyState,
      });

      if (!valid) {
        throw new Error("Sender signature verification failed");
      }
    }

    const topicAddr: TopicAddress = { recipient, topic };
    const result = await this.store.store(topicAddr, payload);
    return { ordinal: result.ordinal, digest: result.digest };
  }
}
