/**
 * @kerizon/signify-client — thin wallet SDK for KERI signing at the edge.
 */

export type { SecurityTier, Keeper, SignifyClient } from './types.js';
export { SimpleKeeper } from './keeper.js';
export type {
  IdentifierResource,
  CredentialResource,
  RegistryResource,
  ExchangeResource,
  OobiResource,
  SignifyResources,
} from './resources.js';
