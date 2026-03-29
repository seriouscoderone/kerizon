/**
 * Tholder — signing threshold satisfaction checker.
 *
 * Supports two threshold modes:
 *
 * **Simple** — `sith` is a hex string (e.g. "1", "2", "a").
 *   `satisfy(indices)` returns true when `indices.length >= num`.
 *
 * **Weighted** — `sith` is `string[][]` (array of clauses).
 *   Each clause is an array of fractional weight strings (e.g. "1/2", "1", "0").
 *   For each clause, sum the fractions at the given indices; the clause is satisfied
 *   if the sum >= 1. All clauses must be satisfied.
 */

import { Fraction } from './fraction.js';

export interface TholderOpts {
  sith: string | string[][];
}

export class Tholder {
  private readonly _isWeighted: boolean;
  private readonly _num: number;
  private readonly _clauses: Fraction[][] | null;

  constructor(opts: TholderOpts) {
    if (typeof opts.sith === 'string') {
      this._isWeighted = false;
      this._num = parseInt(opts.sith, 16);
      this._clauses = null;
      if (isNaN(this._num)) {
        throw new Error(`Invalid simple threshold: "${opts.sith}"`);
      }
    } else {
      this._isWeighted = true;
      this._num = -1;
      this._clauses = opts.sith.map((clause) =>
        clause.map((w) => Fraction.parse(w)),
      );
    }
  }

  /**
   * The numeric threshold (simple mode only).
   * @throws if this is a weighted threshold
   */
  get num(): number {
    if (this._isWeighted) {
      throw new Error('num is not available for weighted thresholds');
    }
    return this._num;
  }

  /**
   * Check whether the given signer indices satisfy the threshold.
   *
   * @param indices - array of signer key indices that signed
   * @returns true if the threshold is met
   */
  satisfy(indices: number[]): boolean {
    if (!this._isWeighted) {
      return indices.length >= this._num;
    }

    // Weighted: every clause must be satisfied
    const indexSet = new Set(indices);
    for (const clause of this._clauses!) {
      let sumNum = 0;
      let sumDen = 1; // We'll accumulate as a proper fraction

      for (let i = 0; i < clause.length; i++) {
        if (indexSet.has(i)) {
          // Add clause[i] to sum: sumNum/sumDen + clause[i].num/clause[i].den
          sumNum = sumNum * clause[i].den + clause[i].num * sumDen;
          sumDen = sumDen * clause[i].den;
        }
      }

      // Check if sum >= 1 (i.e. sumNum >= sumDen)
      if (sumNum < sumDen) {
        return false;
      }
    }

    return true;
  }
}
