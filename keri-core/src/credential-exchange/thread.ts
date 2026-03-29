/**
 * IPEX negotiation state machine.
 *
 * Tracks the state of a single credential exchange thread,
 * enforcing valid transitions per the IPEX protocol.
 */

import type { Serder } from '@kerizon/cesr';
import { NegotiationState, VALID_TRANSITIONS } from './types.js';

export class NegotiationStateMachine {
  private _state: NegotiationState = NegotiationState.Idle;
  private _history: string[] = [];

  get state(): NegotiationState {
    return this._state;
  }

  get history(): readonly string[] {
    return this._history;
  }

  /**
   * Apply a message to advance the state machine.
   *
   * @param message - A Serder exn message (from an IPEX builder)
   * @throws Error if the transition is invalid from the current state
   */
  apply(message: Serder): void {
    const route = message.ked['r'] as string;
    const transitions = VALID_TRANSITIONS.get(this._state);

    if (!transitions) {
      throw new Error(
        `Cannot transition from terminal state ${this._state}`,
      );
    }

    const nextState = transitions.get(route);
    if (nextState === undefined) {
      throw new Error(
        `Invalid transition: ${this._state} + ${route}`,
      );
    }

    this._state = nextState;
    this._history.push(message.said);
  }
}
