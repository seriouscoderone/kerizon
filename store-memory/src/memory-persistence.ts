/**
 * MemoryPersistence -- in-memory implementation of PersistencePort.
 *
 * Re-exports the canonical MemoryPersistence from @kerizon/keri-core so
 * consumers that depend on @kerizon/store-memory get the same implementation.
 * This thin wrapper exists so the adapter follows the same package convention
 * as @kerizon/store-nedb, @kerizon/store-dynamodb, etc.
 */

export { MemoryPersistence } from '@kerizon/keri-core';
