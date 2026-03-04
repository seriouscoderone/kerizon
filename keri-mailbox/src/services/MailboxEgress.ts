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
 * Optionally performs challenge-response authentication before yielding messages.
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
   * recipient's key state before yielding any messages.
   *
   * Yields EgressEvent objects in topic/ordinal order as provided by the store.
   *
   * Throws if:
   *   - Challenge-response authentication is requested and fails.
   *   - The key state cannot be resolved for the recipient (auth only).
   */
  async *poll(params: PollParams): AsyncIterable<EgressEvent> {
    const { recipient, cursors, challenge, signature } = params;

    if (challenge !== undefined && signature !== undefined) {
      const keyState = await this.resolver.resolve(recipient);
      if (!keyState) {
        throw new Error(
          `Cannot resolve key state for recipient ${recipient}`,
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
