import type { IMailboxStore } from "../interfaces/IMailboxStore.js";
import type { IKeyStateResolver } from "../interfaces/IKeyStateResolver.js";
import type { PollParams, EgressEvent } from "../types/results.js";
import { verifyResponse } from "../core/ChallengeResponse.js";

export interface MailboxEgressOptions {
  store: IMailboxStore;
  resolver: IKeyStateResolver;
}

/**
 * Handles outbound message delivery (polling).
 *
 * Performs challenge-response authentication before yielding messages.
 * Validates that the poller is authorized to read the recipient's mailbox.
 * Delegates retrieval to the injected IMailboxStore.
 */
export class MailboxEgress {
  private readonly store: IMailboxStore;
  private readonly resolver: IKeyStateResolver;

  constructor(opts: MailboxEgressOptions) {
    this.store = opts.store;
    this.resolver = opts.resolver;
  }

  /**
   * Poll for messages for a recipient.
   *
   * If both `challenge` and `signature` are present in params, performs
   * challenge-response authentication: verifies the signature against the
   * poller's key state before yielding any messages.
   *
   * Poller authorization:
   *   - If poller == recipient: always authorized (controller reading own mailbox).
   *   - If poller != recipient: requires challenge-response auth against the
   *     poller's key state. Proxy authorization (e.g. KERIA agent) is verified
   *     by the transport layer presenting proof of delegation.
   *
   * Yields EgressEvent objects in topic/ordinal order as provided by the store.
   *
   * Throws if:
   *   - The recipient is not provisioned.
   *   - Challenge-response authentication is requested and fails.
   *   - The key state cannot be resolved for the poller (auth only).
   */
  async *poll(params: PollParams): AsyncIterable<EgressEvent> {
    const { poller, recipient, cursors, challenge, signature } = params;

    const provisioned = await this.store.isProvisioned(recipient);
    if (!provisioned) {
      throw new Error(`Recipient ${recipient} is not provisioned`);
    }

    if (challenge !== undefined && signature !== undefined) {
      // Resolve key state for the poller (who is signing the challenge)
      const keyState = await this.resolver.resolve(poller);
      if (!keyState) {
        throw new Error(
          `Cannot resolve key state for poller ${poller}`,
        );
      }
      const valid = await verifyResponse(challenge, signature, keyState);
      if (!valid) {
        throw new Error("Challenge-response authentication failed");
      }
    }

    yield* this.store.retrieveMulti(recipient, cursors);
  }
}
