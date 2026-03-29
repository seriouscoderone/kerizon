# Layer 1: CESR Root API + Identity Thresholds

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete layer 1 by adding CESR top-level convenience API (encode/decode/sniff) and identity/thresholds features (dual threshold, witness config, Tholder enhancements).

**Architecture:** Small additions to existing `cesr/` and `keri-core/` packages. No new packages. Adds missing port contracts from the spec: `port://cesr/inbound/encoding`, `port://identity/thresholds/inbound/dual-threshold`, `port://identity/thresholds/inbound/witness-configuration`.

**Tech Stack:** TypeScript, vitest, @noble/hashes, @kerizon/cesr

---

## File Structure

```
cesr/
  src/
    codec.ts                    # NEW: top-level encode/decode/sniff API
  tests/
    codec.test.ts               # NEW

keri-core/
  src/
    thresholds/
      dual-threshold.ts         # NEW: check_dual_threshold
      witness-config.ts         # NEW: WitnessConfiguration + apply changes
      types.ts                  # NEW: threshold types
    index.ts                    # MODIFY: add exports
  tests/
    thresholds/
      dual-threshold.test.ts    # NEW
      witness-config.test.ts    # NEW
```

---

### Task 1: CESR top-level codec API

**Files:**
- Create: `cesr/src/codec.ts`
- Test: `cesr/tests/codec.test.ts`
- Modify: `cesr/src/index.ts`

- [ ] **Step 1: Write failing test**

```typescript
// cesr/tests/codec.test.ts
import { describe, it, expect } from 'vitest';
import { encode, decode, sniff } from '../src/codec.js';

describe('CESR codec', () => {
  it('encode(code, raw) produces qb64 string', () => {
    const raw = new Uint8Array(32).fill(0x42);
    const qb64 = encode('D', raw);
    expect(qb64).toHaveLength(44);
    expect(qb64.startsWith('D')).toBe(true);
  });

  it('decode(qb64) recovers code and raw', () => {
    const raw = new Uint8Array(32).fill(0x42);
    const qb64 = encode('D', raw);
    const result = decode(qb64);
    expect(result.code).toBe('D');
    expect(result.raw).toEqual(raw);
  });

  it('round-trip: decode(encode(code, raw)) == (code, raw)', () => {
    const raw = new Uint8Array(64).fill(0x7f);
    const qb64 = encode('0B', raw);
    const result = decode(qb64);
    expect(result.code).toBe('0B');
    expect(result.raw).toEqual(raw);
  });

  it('sniff detects JSON body', () => {
    const jsonStart = new TextEncoder().encode('{"v":"KERI');
    expect(sniff(jsonStart)).toBe('JSON');
  });

  it('sniff detects CBOR body', () => {
    // CBOR map starts with 0xa (tritet 0b101 = 5)
    const cbor = new Uint8Array([0xa2]);
    expect(sniff(cbor)).toBe('CBOR');
  });

  it('sniff detects MGPK body', () => {
    // MGPK FixMap starts with 0x8 (tritet 0b100 = 4)
    const mgpk = new Uint8Array([0x82]);
    expect(sniff(mgpk)).toBe('MGPK');
  });

  it('sniff detects CESR count code', () => {
    // '-' is 0x2d, tritet = 0x2d >> 5 = 1 (count code)
    const cesr = new TextEncoder().encode('-AAB');
    expect(sniff(cesr)).toBe('CESR');
  });

  it('sniff returns null for empty input', () => {
    expect(sniff(new Uint8Array(0))).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd cesr && npx vitest run tests/codec.test.ts`
Expected: FAIL — `encode` not found

- [ ] **Step 3: Implement codec.ts**

```typescript
// cesr/src/codec.ts
/**
 * Top-level CESR encode/decode/sniff API.
 *
 * Implements port://cesr/inbound/encoding from the spec.
 */

import { Matter } from './primitives/matter.js';

/**
 * Encode raw bytes with a CESR code to produce a qb64 string.
 */
export function encode(code: string, raw: Uint8Array): string {
  return new Matter({ code, raw }).qb64;
}

/**
 * Decode a qb64 string back to (code, raw).
 */
export function decode(qb64: string): { code: string; raw: Uint8Array } {
  const m = new Matter({ qb64 });
  return { code: m.code, raw: m.raw };
}

/**
 * Cold-start sniff: detect the serialization kind from the first byte(s).
 *
 * Uses the CESR tritet dispatch (first byte >> 5):
 *   0 (0b000): Annotated T-domain
 *   1 (0b001): CESR count code / T-domain group
 *   2 (0b010): CESR op code
 *   3 (0b011): JSON ('{' = 0x7b, 0x7b >> 5 = 3)
 *   4 (0b100): MGPK FixMap (0x80-0x8f)
 *   5 (0b101): CBOR Map (0xa0-0xbf)
 *   6 (0b110): MGPK Map16/Map32 (0xde, 0xdf)
 *   7 (0b111): CESR B-domain
 */
export type SerializationKind = 'JSON' | 'CBOR' | 'MGPK' | 'CESR' | null;

export function sniff(data: Uint8Array): SerializationKind {
  if (data.length === 0) return null;
  const tritet = data[0] >> 5;
  switch (tritet) {
    case 3: return 'JSON';
    case 4: return 'MGPK';
    case 5: return 'CBOR';
    case 6: return 'MGPK';
    case 1:
    case 2:
    case 7: return 'CESR';
    case 0: return 'CESR';
    default: return null;
  }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd cesr && npx vitest run tests/codec.test.ts`
Expected: PASS (8 tests)

- [ ] **Step 5: Update cesr/src/index.ts**

Add: `export { encode, decode, sniff } from './codec.js';`
Add: `export type { SerializationKind } from './codec.js';`

- [ ] **Step 6: Run full cesr test suite**

Run: `cd cesr && npx vitest run`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add cesr/src/codec.ts cesr/tests/codec.test.ts cesr/src/index.ts
git commit -m "feat(cesr): add top-level encode/decode/sniff API"
```

---

### Task 2: Dual threshold verification

**Files:**
- Create: `keri-core/src/thresholds/dual-threshold.ts`
- Create: `keri-core/src/thresholds/types.ts`
- Test: `keri-core/tests/thresholds/dual-threshold.test.ts`
- Modify: `keri-core/src/index.ts`

- [ ] **Step 1: Write failing test**

```typescript
// keri-core/tests/thresholds/dual-threshold.test.ts
import { describe, it, expect } from 'vitest';
import { checkDualThreshold } from '../../src/thresholds/dual-threshold.js';
import { Tholder } from '@kerizon/cesr';

describe('dual threshold', () => {
  it('passes when both signing and rotation thresholds are met', () => {
    const signing = new Tholder({ sith: '2' });
    const rotation = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, rotation, [0, 1], [0]);
    expect(result.satisfied).toBe(true);
  });

  it('fails when signing threshold is not met', () => {
    const signing = new Tholder({ sith: '2' });
    const rotation = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, rotation, [0], [0]);
    expect(result.satisfied).toBe(false);
    expect(result.reason).toContain('signing');
  });

  it('fails when rotation threshold is not met', () => {
    const signing = new Tholder({ sith: '1' });
    const rotation = new Tholder({ sith: '2' });
    const result = checkDualThreshold(signing, rotation, [0], [0]);
    expect(result.satisfied).toBe(false);
    expect(result.reason).toContain('rotation');
  });

  it('fails when neither threshold is met', () => {
    const signing = new Tholder({ sith: '3' });
    const rotation = new Tholder({ sith: '3' });
    const result = checkDualThreshold(signing, rotation, [0], [0]);
    expect(result.satisfied).toBe(false);
  });

  it('works with weighted signing threshold', () => {
    const signing = new Tholder({ sith: [['1/2', '1/2', '1/2']] });
    const rotation = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, rotation, [0, 1], [0]);
    expect(result.satisfied).toBe(true);
  });

  it('inception has no dual threshold (only signing)', () => {
    const signing = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, null, [0], []);
    expect(result.satisfied).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd keri-core && npx vitest run tests/thresholds/dual-threshold.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement**

```typescript
// keri-core/src/thresholds/types.ts
export interface DualThresholdResult {
  satisfied: boolean;
  reason?: string;
}

// keri-core/src/thresholds/dual-threshold.ts
import type { Tholder } from '@kerizon/cesr';
import type { DualThresholdResult } from './types.js';

/**
 * Check dual threshold for rotation events.
 *
 * Rotation requires BOTH:
 * 1. Signing threshold (kt) satisfied by indices of verified sigs
 * 2. Rotation threshold (nt from PRIOR event) satisfied by ondices
 *
 * For inception, rotationThreshold is null (only signing checked).
 */
export function checkDualThreshold(
  signingThreshold: Tholder,
  rotationThreshold: Tholder | null,
  indices: number[],
  ondices: number[],
): DualThresholdResult {
  if (!signingThreshold.satisfy(indices)) {
    return { satisfied: false, reason: 'signing threshold not met' };
  }
  if (rotationThreshold && !rotationThreshold.satisfy(ondices)) {
    return { satisfied: false, reason: 'rotation threshold not met' };
  }
  return { satisfied: true };
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd keri-core && npx vitest run tests/thresholds/dual-threshold.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add keri-core/src/thresholds/ keri-core/tests/thresholds/
git commit -m "feat(keri-core): add dual threshold verification for rotation events"
```

---

### Task 3: Witness configuration management

**Files:**
- Create: `keri-core/src/thresholds/witness-config.ts`
- Test: `keri-core/tests/thresholds/witness-config.test.ts`
- Modify: `keri-core/src/index.ts`

- [ ] **Step 1: Write failing test**

```typescript
// keri-core/tests/thresholds/witness-config.test.ts
import { describe, it, expect } from 'vitest';
import {
  buildWitnessConfig,
  applyWitnessChanges,
  enoughReceipts,
  type WitnessConfiguration,
} from '../../src/thresholds/witness-config.js';

describe('witness configuration', () => {
  it('builds config from witness list and toad', () => {
    const config = buildWitnessConfig(['W1', 'W2', 'W3'], 2);
    expect(config.witnesses).toEqual(['W1', 'W2', 'W3']);
    expect(config.toad).toBe(2);
  });

  it('rejects toad > witness count', () => {
    expect(() => buildWitnessConfig(['W1'], 3)).toThrow();
  });

  it('rejects toad < 0', () => {
    expect(() => buildWitnessConfig(['W1'], -1)).toThrow();
  });

  it('rejects duplicate witnesses', () => {
    expect(() => buildWitnessConfig(['W1', 'W1'], 1)).toThrow();
  });

  it('applies removals before additions', () => {
    const config = buildWitnessConfig(['W1', 'W2', 'W3'], 2);
    const updated = applyWitnessChanges(config, ['W1'], ['W4']);
    expect(updated.witnesses).toEqual(['W2', 'W3', 'W4']);
    expect(updated.toad).toBe(2);
  });

  it('updates toad when provided', () => {
    const config = buildWitnessConfig(['W1', 'W2', 'W3'], 2);
    const updated = applyWitnessChanges(config, [], ['W4'], 3);
    expect(updated.toad).toBe(3);
  });

  it('rejects adding a witness already in the list', () => {
    const config = buildWitnessConfig(['W1', 'W2'], 1);
    expect(() => applyWitnessChanges(config, [], ['W1'])).toThrow();
  });

  it('rejects removing a witness not in the list', () => {
    const config = buildWitnessConfig(['W1', 'W2'], 1);
    expect(() => applyWitnessChanges(config, ['W3'], [])).toThrow();
  });

  it('enoughReceipts returns true when count >= toad', () => {
    const config = buildWitnessConfig(['W1', 'W2', 'W3'], 2);
    expect(enoughReceipts(config, [0, 1])).toBe(true);
    expect(enoughReceipts(config, [0, 1, 2])).toBe(true);
  });

  it('enoughReceipts returns false when count < toad', () => {
    const config = buildWitnessConfig(['W1', 'W2', 'W3'], 2);
    expect(enoughReceipts(config, [0])).toBe(false);
    expect(enoughReceipts(config, [])).toBe(false);
  });

  it('toad=0 with empty witness list is valid (direct mode)', () => {
    const config = buildWitnessConfig([], 0);
    expect(enoughReceipts(config, [])).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd keri-core && npx vitest run tests/thresholds/witness-config.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement**

```typescript
// keri-core/src/thresholds/witness-config.ts

export interface WitnessConfiguration {
  readonly witnesses: string[];
  readonly toad: number;
}

export function buildWitnessConfig(
  witnesses: string[],
  toad: number,
): WitnessConfiguration {
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
  // Validate removals exist
  for (const r of removals) {
    if (!current.witnesses.includes(r)) {
      throw new Error(`cannot remove witness "${r}" — not in current list`);
    }
  }
  // Apply removals first
  const after = current.witnesses.filter(w => !removals.includes(w));
  // Validate additions don't conflict
  for (const a of additions) {
    if (after.includes(a)) {
      throw new Error(`cannot add witness "${a}" — already in list after removals`);
    }
  }
  after.push(...additions);
  const toad = newToad ?? current.toad;
  return buildWitnessConfig(after, toad);
}

export function enoughReceipts(
  config: WitnessConfiguration,
  receiptIndices: number[],
): boolean {
  return receiptIndices.length >= config.toad;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd keri-core && npx vitest run tests/thresholds/witness-config.test.ts`
Expected: PASS (11 tests)

- [ ] **Step 5: Update keri-core/src/index.ts**

Add exports for `checkDualThreshold`, `DualThresholdResult`, `buildWitnessConfig`, `applyWitnessChanges`, `enoughReceipts`, `WitnessConfiguration`.

- [ ] **Step 6: Run full keri-core suite**

Run: `cd keri-core && npx vitest run`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add keri-core/src/thresholds/ keri-core/tests/thresholds/ keri-core/src/index.ts
git commit -m "feat(keri-core): add witness config management and dual threshold"
```

---

## Self-Review

**Spec coverage:**
- `port://cesr/inbound/encoding`: encode/decode ✓, convert (not needed — Matter handles domain transforms)
- `port://cesr/inbound/code-lookup`: lookup via MtrSizage already exported ✓, list_codes (trivial — `Object.entries(MtrSizage)`)
- `port://identity/thresholds/inbound/threshold-satisfaction`: satisfy ✓ (Tholder), parse_threshold ✓ (Tholder constructor), threshold_size (Tholder.num), is_weighted (can add as getter)
- `port://identity/thresholds/inbound/dual-threshold`: checkDualThreshold ✓
- `port://identity/thresholds/inbound/witness-configuration`: buildWitnessConfig ✓, applyWitnessChanges ✓, enoughReceipts ✓
- GroupCoordination type: deferred (multi-sig coordination is a higher-layer concern requiring messaging infrastructure)
- sniff() for cold start: ✓

**Placeholder scan:** None found.

**Type consistency:** Tholder from `@kerizon/cesr` used consistently in dual-threshold. WitnessConfiguration is a standalone type. No conflicts.

---

Plan complete and saved to `docs/superpowers/plans/2026-03-29-layer1-cesr-thresholds.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?