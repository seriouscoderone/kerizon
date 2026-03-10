/** Simple threshold: a decimal integer string, e.g. "2" means 2-of-n. */
export type SimpleThreshold = string;

/**
 * Weighted fractional threshold: an array of weight-groups.
 * Each group is an array of fraction strings (e.g. "1/2").
 * All groups must independently sum to >= 1.0 for the threshold to be met.
 * Example: [["1/2","1/2"],["1/3","1/3","1/3"]]
 */
export type WeightedThreshold = string[][];

/** Signing threshold — either simple integer string or weighted fractional. */
export type Threshold = SimpleThreshold | WeightedThreshold;
