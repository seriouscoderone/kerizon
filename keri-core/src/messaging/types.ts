export type MessageType = 'icp' | 'rot' | 'ixn' | 'dip' | 'drt' | 'rct' | 'qry' | 'rpy' | 'exn';

export interface ExchangeConfig {
  route: string;
  sender: string;
  payload: Record<string, unknown>;
  embeds?: Record<string, unknown>;
  prior?: string;
  datetime?: string;
}

export interface QueryConfig {
  route: string;
  replyRoute: string;
  query: Record<string, unknown>;
  datetime?: string;
}

export interface ReplyConfig {
  route: string;
  data: Record<string, unknown>;
  datetime?: string;
}
