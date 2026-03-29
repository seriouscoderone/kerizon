import type { BadaRecord, BadaTier } from './types.js';

const TIER_RANK: Record<BadaTier, number> = {
  'signed-anchored': 3,
  'signed': 2,
  'unsigned': 1,
};

export function shouldAccept(existing: BadaRecord | null, incoming: BadaRecord): boolean {
  if (!existing) return true;
  const existingRank = TIER_RANK[existing.tier];
  const incomingRank = TIER_RANK[incoming.tier];
  if (incomingRank > existingRank) return true;
  if (incomingRank < existingRank) return false;
  // Same tier: newer datetime wins
  return incoming.datetime > existing.datetime;
}
