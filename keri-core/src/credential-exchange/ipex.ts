/**
 * IPEX message builders.
 *
 * Each function creates an exn (exchange) message for one step of the
 * IPEX credential issuance / presentation protocol.
 * All return a Serder with a verified SAID.
 */

import { Serder } from '@kerizon/cesr';
import {
  IPEX_ROUTES,
  type ApplyConfig,
  type OfferConfig,
  type AgreeConfig,
  type GrantConfig,
  type AdmitConfig,
  type SpurnConfig,
} from './types.js';

function buildExn(route: string, sender: string, payload: Record<string, unknown>, opts: {
  prior?: string;
  embeds?: Record<string, unknown>;
  datetime?: string;
}): Serder {
  const dt = opts.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'exn', d: '', i: sender, rp: '',
    p: opts.prior ?? '', dt, r: route,
    q: {}, a: payload, e: opts.embeds ?? {},
  };
  return Serder.fromKed(ked);
}

export function buildApply(config: ApplyConfig): Serder {
  return buildExn(IPEX_ROUTES.apply, config.sender, config.payload, {
    datetime: config.datetime,
  });
}

export function buildOffer(config: OfferConfig): Serder {
  return buildExn(IPEX_ROUTES.offer, config.sender, config.payload, {
    prior: config.prior,
    datetime: config.datetime,
  });
}

export function buildAgree(config: AgreeConfig): Serder {
  return buildExn(IPEX_ROUTES.agree, config.sender, {}, {
    prior: config.prior,
    datetime: config.datetime,
  });
}

export function buildGrant(config: GrantConfig): Serder {
  return buildExn(IPEX_ROUTES.grant, config.sender, config.payload, {
    prior: config.prior,
    embeds: { acdc: config.acdc },
    datetime: config.datetime,
  });
}

export function buildAdmit(config: AdmitConfig): Serder {
  return buildExn(IPEX_ROUTES.admit, config.sender, {}, {
    prior: config.prior,
    datetime: config.datetime,
  });
}

export function buildSpurn(config: SpurnConfig): Serder {
  return buildExn(IPEX_ROUTES.spurn, config.sender, {}, {
    prior: config.prior,
    datetime: config.datetime,
  });
}
