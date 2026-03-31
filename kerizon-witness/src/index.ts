/**
 * @kerizon/witness — KERI witness node with pluggable persistence.
 */

export { KerizonWitness } from './witness.js';
export type { WitnessConfig } from './witness.js';
export type { PersistencePort } from '@kerizon/keri-core';
/** @deprecated Use `PersistencePort` from `@kerizon/keri-core` directly. */
export type { WitnessStore } from './store/types.js';
export { NedbStore } from './store/nedb-store.js';
export type { WitnessHandler, TransportServer, CreateTransportServer } from './ports.js';
