/**
 * Credential exchange orchestrator — facade that ties IPEX messaging
 * with the negotiation state machine and credential proof verification.
 */

import { Serder } from '@kerizon/cesr';
import { buildGrant, buildAdmit } from './ipex.js';
import { NegotiationStateMachine } from './thread.js';
import { NegotiationState, IPEX_ROUTES } from './types.js';

export class CredentialExchange {
  private threads = new Map<string, NegotiationStateMachine>();

  /**
   * Direct issuance: issuer grants credential to holder.
   *
   * Creates a grant message and initializes a new negotiation thread,
   * advancing it to the Granted state.
   */
  initiateIssuance(opts: {
    issuerAid: string;
    holderAid: string;
    acdc: Record<string, unknown>;
    datetime?: string;
  }): { grant: Serder; threadId: string } {
    const grant = buildGrant({
      sender: opts.issuerAid,
      payload: { holder: opts.holderAid },
      acdc: opts.acdc,
      datetime: opts.datetime,
    });

    const thread = new NegotiationStateMachine();
    thread.apply(grant);

    const threadId = grant.said;
    this.threads.set(threadId, thread);

    return { grant, threadId };
  }

  /**
   * Process an incoming IPEX message: advance the thread state machine.
   *
   * If no threadId is provided, the message's SAID is used as the
   * thread identifier. If the thread does not exist, a new one is created.
   */
  processMessage(msg: {
    said: string;
    route: string;
    threadId?: string;
  }): { state: string; thread: NegotiationStateMachine } {
    const threadId = msg.threadId ?? msg.said;

    let thread = this.threads.get(threadId);
    if (!thread) {
      thread = new NegotiationStateMachine();
      this.threads.set(threadId, thread);
    }

    // Build a minimal Serder-compatible message for the state machine.
    // The state machine only reads ked['r'] and said.
    const fakeKed: Record<string, unknown> = {
      t: 'exn', d: msg.said, i: '', r: msg.route,
      p: '', q: {}, a: {}, e: {},
    };
    const serder = Serder.fromKed(fakeKed);
    thread.apply(serder);

    return { state: thread.state, thread };
  }

  /** Get thread by ID. */
  getThread(threadId: string): NegotiationStateMachine | undefined {
    return this.threads.get(threadId);
  }
}
