/**
 * Credential lifecycle facade — top-level API for creating registries,
 * issuing credentials, and revoking credentials.
 */

import { createRegistry, createUpdate } from './registry.js';
import { RegistryManager } from './manager.js';
import type { Serder } from '@kerizon/cesr';
import type { CredentialStatus, RegistryMode } from './types.js';

export class CredentialLifecycle {
  private manager = new RegistryManager();

  /**
   * Create a new credential registry.
   *
   * @returns the registry inception Serder and the computed registry SAID
   */
  createRegistry(opts: {
    issuerAid: string;
    name: string;
    mode?: RegistryMode;
  }): { serder: Serder; regid: string } {
    const serder = createRegistry({
      issuerAid: opts.issuerAid,
      datetime: new Date().toISOString(),
    });
    const regid = serder.said;

    this.manager.register({
      registrySaid: regid,
      issuerAid: opts.issuerAid,
      name: opts.name,
      mode: opts.mode ?? 'non-blindable',
      createdAt: new Date().toISOString(),
    });

    return { serder, regid };
  }

  /**
   * Issue a credential in the specified registry.
   *
   * @throws if the registry is unknown or the credential is already issued
   */
  issue(opts: {
    registryName: string;
    credentialSaid: string;
    datetime?: string;
  }): Serder {
    const record = this.manager.getRegistryByName(opts.registryName);
    if (!record) {
      throw new Error(`Unknown registry: ${opts.registryName}`);
    }

    const tel = this.manager.getTel(record.registrySaid)!;
    const current = tel.getState(opts.credentialSaid);

    const serder = createUpdate({
      registrySaid: record.registrySaid,
      credentialSaid: opts.credentialSaid,
      priorSaid: current.sn === 0 ? record.registrySaid : opts.credentialSaid,
      sn: current.sn + 1,
      targetState: 'Issued',
      datetime: opts.datetime,
    });

    tel.apply(serder);
    return serder;
  }

  /**
   * Revoke a credential in the specified registry.
   *
   * @throws if the registry is unknown or the credential is not in Issued state
   */
  revoke(opts: {
    registryName: string;
    credentialSaid: string;
    datetime?: string;
  }): Serder {
    const record = this.manager.getRegistryByName(opts.registryName);
    if (!record) {
      throw new Error(`Unknown registry: ${opts.registryName}`);
    }

    const tel = this.manager.getTel(record.registrySaid)!;
    const current = tel.getState(opts.credentialSaid);

    const serder = createUpdate({
      registrySaid: record.registrySaid,
      credentialSaid: opts.credentialSaid,
      priorSaid: opts.credentialSaid,
      sn: current.sn + 1,
      targetState: 'Revoked',
      datetime: opts.datetime,
    });

    tel.apply(serder);
    return serder;
  }

  /**
   * Get the current state of a credential in the specified registry.
   *
   * @throws if the registry is unknown
   */
  getState(registryName: string, credentialSaid: string): CredentialStatus {
    const record = this.manager.getRegistryByName(registryName);
    if (!record) {
      throw new Error(`Unknown registry: ${registryName}`);
    }

    const tel = this.manager.getTel(record.registrySaid)!;
    return tel.getState(credentialSaid);
  }

  /** Access the underlying RegistryManager. */
  getRegistryManager(): RegistryManager {
    return this.manager;
  }
}
