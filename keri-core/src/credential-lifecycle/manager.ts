import type { RegistryRecord } from './types.js';
import { TelStateMachine } from './tel.js';

/**
 * Manages multiple credential registries with name and SAID lookups.
 *
 * Each registered registry gets an associated TelStateMachine for
 * tracking credential lifecycle states within that registry.
 */
export class RegistryManager {
  private readonly registries = new Map<string, RegistryRecord>();
  private readonly nameIndex = new Map<string, string>();
  private readonly tels = new Map<string, TelStateMachine>();

  /**
   * Register a new registry record.
   *
   * @throws if a registry with the same name already exists
   */
  register(record: RegistryRecord): void {
    if (this.nameIndex.has(record.name)) {
      throw new Error(
        `Registry with name '${record.name}' already exists`,
      );
    }
    this.registries.set(record.registrySaid, record);
    this.nameIndex.set(record.name, record.registrySaid);
    this.tels.set(record.registrySaid, new TelStateMachine(record.registrySaid));
  }

  /** Look up a registry by its SAID (REGID). */
  getRegistry(regid: string): RegistryRecord | undefined {
    return this.registries.get(regid);
  }

  /** Look up a registry by its human-readable name. */
  getRegistryByName(name: string): RegistryRecord | undefined {
    const regid = this.nameIndex.get(name);
    return regid !== undefined ? this.registries.get(regid) : undefined;
  }

  /** Get the TEL state machine for a registry. */
  getTel(regid: string): TelStateMachine | undefined {
    return this.tels.get(regid);
  }

  /** List all registered registries. */
  listRegistries(): RegistryRecord[] {
    return Array.from(this.registries.values());
  }
}
