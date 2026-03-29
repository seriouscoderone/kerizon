import type { OobiParts, OobiRole } from './types.js';

export function parseOobi(url: string): OobiParts {
  const u = new URL(url);
  const parts = u.pathname.split('/').filter(Boolean);

  // Well-known: /.well-known/keri/oobi/{cid}
  if (parts[0] === '.well-known' && parts[1] === 'keri' && parts[2] === 'oobi') {
    return { url, cid: parts[3] };
  }

  // Standard: /oobi/{cid}/{role}[/{eid}]
  if (parts[0] === 'oobi') {
    return {
      url,
      cid: parts[1],
      role: parts[2] as OobiRole | undefined,
      eid: parts[3],
    };
  }

  return { url };
}

export function formatOobi(base: string, parts: { cid: string; role?: OobiRole; eid?: string }): string {
  let path = `/oobi/${parts.cid}`;
  if (parts.role) path += `/${parts.role}`;
  if (parts.eid) path += `/${parts.eid}`;
  return `${base}${path}`;
}
