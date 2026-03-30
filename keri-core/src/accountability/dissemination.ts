/**
 * Witness dissemination — round-robin event propagation between witnesses.
 *
 * After a controller submits an event to one witness, witnesses propagate
 * to each other. Total exchanges <= 2*N where N is witness count.
 */

export interface DisseminationConfig {
  readonly witnesses: string[]; // witness AIDs
  readonly mode: 'direct' | 'indirect'; // direct = bt==0, indirect = bt>=1
}

export interface DisseminationPlan {
  readonly exchanges: Array<{ from: string; to: string }>;
  readonly maxExchanges: number; // <= 2*N
  readonly bandwidth: number; // <= N * ceil(log2(N+1))
}

/** Build a round-robin dissemination plan for N witnesses. */
export function buildDisseminationPlan(
  witnesses: string[],
): DisseminationPlan {
  const n = witnesses.length;
  if (n === 0) return { exchanges: [], maxExchanges: 0, bandwidth: 0 };

  const exchanges: Array<{ from: string; to: string }> = [];
  // Round-robin: each witness sends to the next
  for (let i = 0; i < n; i++) {
    const next = (i + 1) % n;
    exchanges.push({ from: witnesses[i], to: witnesses[next] });
  }
  // Reverse direction
  for (let i = n - 1; i >= 0; i--) {
    const prev = (i - 1 + n) % n;
    exchanges.push({ from: witnesses[i], to: witnesses[prev] });
  }

  return {
    exchanges,
    maxExchanges: 2 * n,
    bandwidth: n * Math.ceil(Math.log2(n + 1)),
  };
}

/** Classify dissemination mode from witness config. */
export function classifyMode(
  witnessCount: number,
  toad: number,
): 'direct' | 'indirect' {
  return toad === 0 && witnessCount === 0 ? 'direct' : 'indirect';
}
