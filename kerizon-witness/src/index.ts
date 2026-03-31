/**
 * @kerizon/witness — KERI witness node with NeDB persistence.
 */

export { KerizonWitness } from './witness.js';
export type { WitnessConfig } from './witness.js';
export type { WitnessStore } from './store/types.js';
export { NedbStore } from './store/nedb-store.js';
export type { WitnessHandler, TransportServer, CreateTransportServer } from './ports.js';
