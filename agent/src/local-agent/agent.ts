/**
 * LocalAgent — the fat wallet. Orchestrates the full KERI stack locally.
 * This is what kerizon-cli wraps.
 */

import type { CredentialLifecycle } from '@kerizon/keri-core';
import type { CredentialExchange } from '@kerizon/keri-core';
import type { WatcherService } from '@kerizon/keri-core';

export interface LocalAgentIdentity {
  /** All managed identifier prefixes. */
  list(): string[];
}

export class LocalAgent {
  readonly identity: LocalAgentIdentity;
  readonly credentials: CredentialLifecycle;
  readonly exchange: CredentialExchange;
  readonly watcher: WatcherService;

  constructor(opts: {
    credentials: CredentialLifecycle;
    exchange: CredentialExchange;
    watcher: WatcherService;
  }) {
    this.credentials = opts.credentials;
    this.exchange = opts.exchange;
    this.watcher = opts.watcher;
    this.identity = { list: () => [] };
  }
}
