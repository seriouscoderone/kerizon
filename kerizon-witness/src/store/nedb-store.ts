/**
 * Re-export NedbPersistence from @kerizon/store-nedb.
 *
 * The old NedbStore class has been superseded by the unified
 * PersistencePort adapter. This file exists for backward compatibility.
 *
 * @deprecated Import `NedbPersistence` from `@kerizon/store-nedb` directly.
 */
export { NedbPersistence as NedbStore } from '@kerizon/store-nedb';
