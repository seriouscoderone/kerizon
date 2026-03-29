export interface WitnessConfiguration {
  readonly witnesses: string[];
  readonly toad: number;
}

export function buildWitnessConfig(witnesses: string[], toad: number): WitnessConfiguration {
  if (toad < 0) throw new Error(`toad must be non-negative, got ${toad}`);
  if (toad > witnesses.length) throw new Error(`toad (${toad}) > witness count (${witnesses.length})`);
  const unique = new Set(witnesses);
  if (unique.size !== witnesses.length) throw new Error('duplicate witnesses');
  return { witnesses: [...witnesses], toad };
}

export function applyWitnessChanges(
  current: WitnessConfiguration,
  removals: string[],
  additions: string[],
  newToad?: number,
): WitnessConfiguration {
  for (const r of removals) {
    if (!current.witnesses.includes(r)) throw new Error(`cannot remove "${r}" — not in list`);
  }
  const after = current.witnesses.filter(w => !removals.includes(w));
  for (const a of additions) {
    if (after.includes(a)) throw new Error(`cannot add "${a}" — already in list`);
  }
  after.push(...additions);
  return buildWitnessConfig(after, newToad ?? current.toad);
}

export function enoughReceipts(config: WitnessConfiguration, receiptIndices: number[]): boolean {
  return receiptIndices.length >= config.toad;
}
