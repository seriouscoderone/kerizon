export type OobiRole = 'witness' | 'watcher' | 'agent' | 'controller' | 'mailbox';

export interface OobiParts {
  url: string;
  cid?: string;    // controller AID
  role?: OobiRole;
  eid?: string;    // endpoint AID
  said?: string;   // for data OOBIs
}

export interface EndRole {
  readonly cid: string;
  readonly role: OobiRole;
  readonly eid: string;
}

export interface LocationScheme {
  readonly eid: string;
  readonly scheme: 'http' | 'https' | 'tcp';
  readonly url: string;
}

export interface ServiceEndpoint {
  readonly serviceAid: string;
  readonly url: string;
  readonly role: OobiRole;
}

export interface ResolvedEndpoint {
  readonly aid: string;
  readonly endpoints: ServiceEndpoint[];
}

export type BadaTier = 'signed-anchored' | 'signed' | 'unsigned';

export interface BadaRecord {
  readonly tier: BadaTier;
  readonly datetime: string;
  readonly data: Record<string, unknown>;
}
