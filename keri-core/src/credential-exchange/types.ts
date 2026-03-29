/**
 * IPEX credential exchange types and constants.
 *
 * Defines the negotiation state machine states, IPEX exchange routes,
 * and valid state transitions for the IPEX protocol.
 */

export enum NegotiationState {
  Idle = 'Idle',
  Applied = 'Applied',
  Offered = 'Offered',
  Agreed = 'Agreed',
  Granted = 'Granted',
  Admitted = 'Admitted',
  Spurned = 'Spurned',
}

export const IPEX_ROUTES = {
  apply: '/ipex/apply',
  offer: '/ipex/offer',
  agree: '/ipex/agree',
  grant: '/ipex/grant',
  admit: '/ipex/admit',
  spurn: '/ipex/spurn',
} as const;

export type IpexRoute = (typeof IPEX_ROUTES)[keyof typeof IPEX_ROUTES];

/**
 * Maps each non-terminal state to the set of routes that are valid from it.
 * Terminal states (Admitted, Spurned) have no valid transitions.
 */
export const VALID_TRANSITIONS: ReadonlyMap<NegotiationState, ReadonlyMap<string, NegotiationState>> = (() => {
  const m = new Map<NegotiationState, Map<string, NegotiationState>>();
  m.set(NegotiationState.Idle, new Map<string, NegotiationState>([
    [IPEX_ROUTES.apply, NegotiationState.Applied],
    [IPEX_ROUTES.grant, NegotiationState.Granted],
  ]));
  m.set(NegotiationState.Applied, new Map<string, NegotiationState>([
    [IPEX_ROUTES.offer, NegotiationState.Offered],
    [IPEX_ROUTES.spurn, NegotiationState.Spurned],
  ]));
  m.set(NegotiationState.Offered, new Map<string, NegotiationState>([
    [IPEX_ROUTES.agree, NegotiationState.Agreed],
    [IPEX_ROUTES.spurn, NegotiationState.Spurned],
  ]));
  m.set(NegotiationState.Agreed, new Map<string, NegotiationState>([
    [IPEX_ROUTES.grant, NegotiationState.Granted],
    [IPEX_ROUTES.spurn, NegotiationState.Spurned],
  ]));
  m.set(NegotiationState.Granted, new Map<string, NegotiationState>([
    [IPEX_ROUTES.admit, NegotiationState.Admitted],
    [IPEX_ROUTES.spurn, NegotiationState.Spurned],
  ]));
  return m;
})();

export interface ApplyConfig {
  sender: string;
  payload: Record<string, unknown>;
  datetime?: string;
}

export interface OfferConfig {
  sender: string;
  payload: Record<string, unknown>;
  prior: string;
  datetime?: string;
}

export interface AgreeConfig {
  sender: string;
  prior: string;
  datetime?: string;
}

export interface GrantConfig {
  sender: string;
  payload: Record<string, unknown>;
  acdc: Record<string, unknown>;
  prior?: string;
  datetime?: string;
}

export interface AdmitConfig {
  sender: string;
  prior: string;
  datetime?: string;
}

export interface SpurnConfig {
  sender: string;
  prior: string;
  datetime?: string;
}
