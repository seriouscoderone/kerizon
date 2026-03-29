/**
 * Fraction — simple rational number for weighted threshold arithmetic.
 *
 * Parses strings like "1/2", "1/3", "1", "0" into numerator/denominator pairs.
 */

export class Fraction {
  readonly num: number;
  readonly den: number;

  constructor(num: number, den: number) {
    if (den === 0) {
      throw new Error('Fraction denominator cannot be zero');
    }
    this.num = num;
    this.den = den;
  }

  /**
   * Parse a fraction string.
   *
   * Formats:
   *   "1/2" → Fraction(1, 2)
   *   "1"   → Fraction(1, 1)
   *   "0"   → Fraction(0, 1)
   */
  static parse(str: string): Fraction {
    const parts = str.split('/');
    if (parts.length === 2) {
      return new Fraction(parseInt(parts[0], 10), parseInt(parts[1], 10));
    }
    return new Fraction(parseInt(str, 10), 1);
  }
}
