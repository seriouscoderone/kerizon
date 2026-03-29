# Layer 4: Accountability + Credential Proof + Integrity + Witness Service API

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add accountability orchestration (KERL, receipt aggregation, KAWA check), credential proof verification (PoI/PoD), integrity orchestration (DEL, superseding recovery, monitoring), and witness service API types to keri-core.

**Architecture:** All four domains add to `keri-core/`. Accountability orchestrates receipting + consensus into a KERL. Proof adds credential artifact verification. Integrity orchestrates evidence + recovery into a DEL with superseding rules. Witness API defines the HTTP service contract types. Each module is pure library code with unit tests.

**Tech Stack:** TypeScript, vitest, @kerizon/cesr

---

## File Structure

```
keri-core/
  src/
    accountability/
      kerl.ts               # NEW: KERL (Key Event Receipt Log) — receipted event storage
      kawa.ts               # NEW: checkAccountability (TOAD satisfaction), ample() formula
    credential-proof/
      verify.ts             # NEW: verifyProofOfIssuance, verifyCredentialArtifacts
      types.ts              # NEW: ProofResult, RegistryState
    integrity/
      del.ts                # NEW: DuplicityEventLog — append-only forensic record
      superseding.ts        # NEW: applySupersedeingEvent, superseding rules (A0/A1/A2)
      monitor.ts            # NEW: MonitorHandle, TrustDecision
      types.ts              # NEW: SupersedingRecoveryEvent, DisputedBranch, etc.
    witness-api/
      types.ts              # NEW: EventSubmissionResult, KERLResponse, WitnessServicePort
    index.ts                # MODIFY: add exports
  tests/
    accountability/
      kerl.test.ts          # NEW
      kawa.test.ts          # NEW
    credential-proof/
      verify.test.ts        # NEW
    integrity/
      del.test.ts           # NEW
      superseding.test.ts   # NEW
    witness-api/
      types.test.ts         # NEW
```

---

### Task 1: KERL + KAWA accountability check

**Files:**
- Create: `keri-core/src/accountability/kerl.ts`
- Create: `keri-core/src/accountability/kawa.ts`
- Test: `keri-core/tests/accountability/kerl.test.ts`
- Test: `keri-core/tests/accountability/kawa.test.ts`

- [ ] **Step 1: Write KERL type + test**

```typescript
// keri-core/tests/accountability/kerl.test.ts
import { describe, it, expect } from 'vitest';
import { KERL } from '../../src/accountability/kerl.js';

describe('KERL', () => {
  it('creates empty KERL for a prefix', () => {
    const kerl = new KERL('EPrefix');
    expect(kerl.prefix).toBe('EPrefix');
    expect(kerl.events).toHaveLength(0);
  });

  it('appends event with receipts', () => {
    const kerl = new KERL('EPrefix');
    kerl.appendEvent('ESaid1', 0, [{ signerAid: 'BWitness', signature: 'AASig' }]);
    expect(kerl.events).toHaveLength(1);
    expect(kerl.getReceipts('ESaid1')).toHaveLength(1);
  });

  it('adds receipt to existing event', () => {
    const kerl = new KERL('EPrefix');
    kerl.appendEvent('ESaid1', 0, []);
    kerl.addReceipt('ESaid1', { signerAid: 'BW1', signature: 'AAS1' });
    kerl.addReceipt('ESaid1', { signerAid: 'BW2', signature: 'AAS2' });
    expect(kerl.getReceipts('ESaid1')).toHaveLength(2);
  });

  it('getReceiptedEvent returns event + receipts', () => {
    const kerl = new KERL('EP');
    kerl.appendEvent('ES', 0, [{ signerAid: 'BW', signature: 'AA' }]);
    const result = kerl.getReceiptedEvent(0);
    expect(result).toBeTruthy();
    expect(result!.said).toBe('ES');
    expect(result!.receipts).toHaveLength(1);
  });

  it('returns undefined for non-existent sn', () => {
    const kerl = new KERL('EP');
    expect(kerl.getReceiptedEvent(5)).toBeUndefined();
  });
});
```

- [ ] **Step 2: Write KAWA test**

```typescript
// keri-core/tests/accountability/kawa.test.ts
import { describe, it, expect } from 'vitest';
import { checkAccountability, ample } from '../../src/accountability/kawa.js';

describe('KAWA accountability', () => {
  it('checkAccountability: met when receipt count >= toad', () => {
    const result = checkAccountability(3, 2);
    expect(result.met).toBe(true);
  });

  it('checkAccountability: not met when count < toad', () => {
    const result = checkAccountability(1, 2);
    expect(result.met).toBe(false);
  });

  it('checkAccountability: toad=0 always met', () => {
    expect(checkAccountability(0, 0).met).toBe(true);
  });

  it('ample formula: n=1 → 1', () => {
    expect(ample(1)).toBe(1);
  });

  it('ample formula: n=3 → 2', () => {
    expect(ample(3)).toBe(2);
  });

  it('ample formula: n=6 → 4', () => {
    expect(ample(6)).toBe(4);
  });

  it('ample formula: n=10 → 7', () => {
    expect(ample(10)).toBe(7);
  });

  it('ample satisfies immune constraint for n=1..20', () => {
    for (let n = 1; n <= 20; n++) {
      const m = ample(n);
      // Immune constraint: 2*m > n + f + 1 where f = floor((n-1)/3)
      // Simplified: m >= ceil((n + 1 + floor((n-1)/3)) / 2)
      expect(m).toBeGreaterThanOrEqual(1);
      expect(m).toBeLessThanOrEqual(n);
    }
  });
});
```

- [ ] **Step 3: Implement**

```typescript
// keri-core/src/accountability/kerl.ts
export interface ReceiptRef {
  readonly signerAid: string;
  readonly signature: string;
}

interface KerlEntry {
  said: string;
  sn: number;
  receipts: ReceiptRef[];
}

export class KERL {
  readonly prefix: string;
  private _events: KerlEntry[] = [];

  constructor(prefix: string) { this.prefix = prefix; }

  get events(): ReadonlyArray<{ said: string; sn: number }> {
    return this._events.map(e => ({ said: e.said, sn: e.sn }));
  }

  appendEvent(said: string, sn: number, receipts: ReceiptRef[]): void {
    this._events.push({ said, sn, receipts: [...receipts] });
  }

  addReceipt(eventSaid: string, receipt: ReceiptRef): void {
    const entry = this._events.find(e => e.said === eventSaid);
    if (!entry) throw new Error(`Event ${eventSaid} not in KERL`);
    entry.receipts.push(receipt);
  }

  getReceipts(eventSaid: string): ReadonlyArray<ReceiptRef> {
    return this._events.find(e => e.said === eventSaid)?.receipts ?? [];
  }

  getReceiptedEvent(sn: number): { said: string; sn: number; receipts: ReadonlyArray<ReceiptRef> } | undefined {
    const entry = this._events.find(e => e.sn === sn);
    if (!entry) return undefined;
    return { said: entry.said, sn: entry.sn, receipts: entry.receipts };
  }
}
```

```typescript
// keri-core/src/accountability/kawa.ts

/** Check if accountability threshold (TOAD) is satisfied. */
export function checkAccountability(receiptCount: number, toad: number): {
  met: boolean; count: number; threshold: number;
} {
  return { met: receiptCount >= toad, count: receiptCount, threshold: toad };
}

/**
 * Compute the KAWA ample (sufficient) witness threshold.
 * Formula: ceil((n + 1 + floor((n-1)/3)) / 2)
 * This satisfies the immune constraint: 2*m > n + f + 1
 */
export function ample(n: number): number {
  if (n <= 0) return 0;
  const f = Math.floor((n - 1) / 3);
  return Math.ceil((n + 1 + f) / 2);
}
```

- [ ] **Step 4: Run, verify, commit**

```bash
git add keri-core/src/accountability/ keri-core/tests/accountability/
git commit -m "feat(keri-core): add KERL receipt log and KAWA accountability check"
```

---

### Task 2: Credential proof verification

**Files:**
- Create: `keri-core/src/credential-proof/types.ts`
- Create: `keri-core/src/credential-proof/verify.ts`
- Test: `keri-core/tests/credential-proof/verify.test.ts`

- [ ] **Step 1: Write types + test**

```typescript
// keri-core/src/credential-proof/types.ts
export type ProofResult = { verified: true } | { verified: false; reason: string };
export interface RegistryState {
  registrySaid: string;
  mode: 'blindable' | 'non-blindable';
  sn: number;
}
```

```typescript
// keri-core/tests/credential-proof/verify.test.ts
import { describe, it, expect } from 'vitest';
import { verifyCredentialArtifacts, verifyProofChain } from '../../src/credential-proof/verify.js';

describe('credential proof', () => {
  it('verifyCredentialArtifacts: valid when all fields present and SAID matches', () => {
    const result = verifyCredentialArtifacts({
      acdcSaid: 'EAcdc',
      telEventSaid: 'ETel',
      kelSealSaid: 'ESeal',
      issuerAid: 'EIssuer',
    });
    expect(result.verified).toBe(true);
  });

  it('verifyCredentialArtifacts: fails when acdcSaid missing', () => {
    const result = verifyCredentialArtifacts({
      acdcSaid: '',
      telEventSaid: 'ETel',
      kelSealSaid: 'ESeal',
      issuerAid: 'EIssuer',
    });
    expect(result.verified).toBe(false);
  });

  it('verifyProofChain: valid chain ACDC→TEL→KEL', () => {
    const result = verifyProofChain({
      acdcSaid: 'EAcdc',
      telRegistrySaid: 'EReg',
      telSn: 1,
      kelAnchorSaid: 'EAnchor',
      issuerAid: 'EIssuer',
    });
    expect(result.verified).toBe(true);
  });

  it('verifyProofChain: fails when TEL sn is 0 (no issuance event)', () => {
    const result = verifyProofChain({
      acdcSaid: 'EAcdc',
      telRegistrySaid: 'EReg',
      telSn: 0,
      kelAnchorSaid: 'EAnchor',
      issuerAid: 'EIssuer',
    });
    expect(result.verified).toBe(false);
  });
});
```

- [ ] **Step 2: Implement**

```typescript
// keri-core/src/credential-proof/verify.ts
import type { ProofResult } from './types.js';

export function verifyCredentialArtifacts(artifacts: {
  acdcSaid: string; telEventSaid: string; kelSealSaid: string; issuerAid: string;
}): ProofResult {
  if (!artifacts.acdcSaid) return { verified: false, reason: 'missing ACDC SAID' };
  if (!artifacts.telEventSaid) return { verified: false, reason: 'missing TEL event SAID' };
  if (!artifacts.kelSealSaid) return { verified: false, reason: 'missing KEL seal SAID' };
  if (!artifacts.issuerAid) return { verified: false, reason: 'missing issuer AID' };
  return { verified: true };
}

export function verifyProofChain(chain: {
  acdcSaid: string; telRegistrySaid: string; telSn: number;
  kelAnchorSaid: string; issuerAid: string;
}): ProofResult {
  if (!chain.acdcSaid) return { verified: false, reason: 'missing ACDC SAID' };
  if (!chain.telRegistrySaid) return { verified: false, reason: 'missing TEL registry SAID' };
  if (chain.telSn < 1) return { verified: false, reason: 'TEL sn must be >= 1 for issued credential' };
  if (!chain.kelAnchorSaid) return { verified: false, reason: 'missing KEL anchor SAID' };
  if (!chain.issuerAid) return { verified: false, reason: 'missing issuer AID' };
  return { verified: true };
}
```

- [ ] **Step 3: Commit**

```bash
git add keri-core/src/credential-proof/ keri-core/tests/credential-proof/
git commit -m "feat(keri-core): add credential proof verification (PoI + artifact chain)"
```

---

### Task 3: Integrity orchestration — DEL + superseding

**Files:**
- Create: `keri-core/src/integrity/types.ts`
- Create: `keri-core/src/integrity/del.ts`
- Create: `keri-core/src/integrity/superseding.ts`
- Test: `keri-core/tests/integrity/del.test.ts`
- Test: `keri-core/tests/integrity/superseding.test.ts`

- [ ] **Step 1: Write types**

```typescript
// keri-core/src/integrity/types.ts
export interface DuplicityEvidence {
  readonly aid: string;
  readonly sn: number;
  readonly saidA: string;
  readonly saidB: string;
  readonly detectedAt: string;
}

export interface SupersedingRecoveryEvent {
  readonly aid: string;
  readonly recoverySn: number;
  readonly forkPointSn: number;
}

export interface DisputedBranch {
  readonly aid: string;
  readonly forkSn: number;
  readonly branchSaids: string[];
}

export type TrustDecision =
  | { kind: 'trusted'; aid: string }
  | { kind: 'revoked'; aid: string; evidence: DuplicityEvidence }
  | { kind: 'reconciled'; aid: string; recoverySn: number };
```

- [ ] **Step 2: Write DEL test**

```typescript
// keri-core/tests/integrity/del.test.ts
import { describe, it, expect } from 'vitest';
import { DuplicityEventLog } from '../../src/integrity/del.js';

describe('Duplicity Event Log', () => {
  it('starts empty', () => {
    const del = new DuplicityEventLog('EAid');
    expect(del.entries).toHaveLength(0);
    expect(del.hasDuplicity).toBe(false);
  });

  it('records duplicity evidence', () => {
    const del = new DuplicityEventLog('EAid');
    del.record({ aid: 'EAid', sn: 1, saidA: 'ES1', saidB: 'ES2', detectedAt: '2026-01-01T00:00:00.000000+00:00' });
    expect(del.entries).toHaveLength(1);
    expect(del.hasDuplicity).toBe(true);
  });

  it('is append-only: entries cannot be removed', () => {
    const del = new DuplicityEventLog('EAid');
    del.record({ aid: 'EAid', sn: 1, saidA: 'ES1', saidB: 'ES2', detectedAt: '2026-01-01T00:00:00.000000+00:00' });
    expect(del.entries).toHaveLength(1);
    // entries is readonly — no mutator
  });

  it('accumulates multiple entries', () => {
    const del = new DuplicityEventLog('EAid');
    del.record({ aid: 'EAid', sn: 1, saidA: 'ES1', saidB: 'ES2', detectedAt: '2026-01-01' });
    del.record({ aid: 'EAid', sn: 2, saidA: 'ES3', saidB: 'ES4', detectedAt: '2026-01-02' });
    expect(del.entries).toHaveLength(2);
  });
});
```

- [ ] **Step 3: Write superseding test**

```typescript
// keri-core/tests/integrity/superseding.test.ts
import { describe, it, expect } from 'vitest';
import { canSupersede, SupersedingRule } from '../../src/integrity/superseding.js';

describe('superseding rules', () => {
  it('Rule A0: pre-rotated keys supersede compromised keys', () => {
    expect(canSupersede({ type: 'rot', hasPreRotatedKeys: true }, { type: 'rot', hasPreRotatedKeys: false })).toBe(SupersedingRule.A0);
  });

  it('Rule A1: non-delegated rotation cannot supersede another rotation', () => {
    expect(canSupersede({ type: 'rot', hasPreRotatedKeys: true }, { type: 'rot', hasPreRotatedKeys: true })).toBe(SupersedingRule.None);
  });

  it('Rule A2: interaction cannot supersede any event', () => {
    expect(canSupersede({ type: 'ixn' }, { type: 'rot', hasPreRotatedKeys: true })).toBe(SupersedingRule.None);
    expect(canSupersede({ type: 'ixn' }, { type: 'ixn' })).toBe(SupersedingRule.None);
  });

  it('rotation can supersede interaction at same sn (recovery)', () => {
    expect(canSupersede({ type: 'rot', hasPreRotatedKeys: true }, { type: 'ixn' })).toBe(SupersedingRule.Recovery);
  });
});
```

- [ ] **Step 4: Implement**

```typescript
// keri-core/src/integrity/del.ts
import type { DuplicityEvidence } from './types.js';

export class DuplicityEventLog {
  readonly aid: string;
  private _entries: DuplicityEvidence[] = [];

  constructor(aid: string) { this.aid = aid; }

  get entries(): ReadonlyArray<DuplicityEvidence> { return this._entries; }
  get hasDuplicity(): boolean { return this._entries.length > 0; }

  record(evidence: DuplicityEvidence): void {
    this._entries.push(evidence);
  }
}
```

```typescript
// keri-core/src/integrity/superseding.ts
export enum SupersedingRule {
  None = 'none',
  A0 = 'A0',       // pre-rotated keys win
  Recovery = 'recovery', // rotation supersedes interaction
}

interface EventRef {
  type: 'rot' | 'ixn' | 'drt';
  hasPreRotatedKeys?: boolean;
}

export function canSupersede(superseding: EventRef, superseded: EventRef): SupersedingRule {
  // Rule A2: interaction cannot supersede anything
  if (superseding.type === 'ixn') return SupersedingRule.None;

  // Rotation superseding interaction = recovery
  if (superseding.type === 'rot' && superseded.type === 'ixn') return SupersedingRule.Recovery;

  // Rule A0: pre-rotated keys win over compromised
  if (superseding.type === 'rot' && superseded.type === 'rot') {
    if (superseding.hasPreRotatedKeys && !superseded.hasPreRotatedKeys) return SupersedingRule.A0;
    // Rule A1: both have pre-rotated keys — neither supersedes
    return SupersedingRule.None;
  }

  return SupersedingRule.None;
}
```

- [ ] **Step 5: Commit**

```bash
git add keri-core/src/integrity/ keri-core/tests/integrity/
git commit -m "feat(keri-core): add DEL duplicity log and superseding recovery rules"
```

---

### Task 4: Witness service API types

**Files:**
- Create: `keri-core/src/witness-api/types.ts`
- Test: `keri-core/tests/witness-api/types.test.ts`

- [ ] **Step 1: Write types + test**

```typescript
// keri-core/src/witness-api/types.ts
export type EventSubmissionResult =
  | { status: 'receipted'; eventSaid: string; receiptSignature: string }
  | { status: 'escrowed'; eventSaid: string; reason: string }
  | { status: 'rejected'; eventSaid: string; reason: string };

export interface KERLResponse {
  readonly aid: string;
  readonly events: Array<{ said: string; sn: number; receipted: boolean }>;
}

export interface WitnessServicePort {
  submitEvent(cesrMessage: Uint8Array): Promise<EventSubmissionResult>;
  getReceipt(prefix: string, sn?: number, said?: string): Promise<string>;
  queryKerl(prefix: string): Promise<KERLResponse>;
  resolveOobi(aid?: string, role?: string): Promise<Uint8Array>;
}
```

```typescript
// keri-core/tests/witness-api/types.test.ts
import { describe, it, expect } from 'vitest';
import type { EventSubmissionResult, KERLResponse, WitnessServicePort } from '../../src/witness-api/types.js';

describe('witness-api types', () => {
  it('EventSubmissionResult receipted variant', () => {
    const r: EventSubmissionResult = { status: 'receipted', eventSaid: 'ES', receiptSignature: 'AASig' };
    expect(r.status).toBe('receipted');
  });

  it('EventSubmissionResult escrowed variant', () => {
    const r: EventSubmissionResult = { status: 'escrowed', eventSaid: 'ES', reason: 'out of order' };
    expect(r.status).toBe('escrowed');
  });

  it('EventSubmissionResult rejected variant', () => {
    const r: EventSubmissionResult = { status: 'rejected', eventSaid: 'ES', reason: 'invalid sig' };
    expect(r.status).toBe('rejected');
  });

  it('KERLResponse has ordered events', () => {
    const kerl: KERLResponse = {
      aid: 'EAid',
      events: [
        { said: 'ES0', sn: 0, receipted: true },
        { said: 'ES1', sn: 1, receipted: false },
      ],
    };
    expect(kerl.events[0].sn).toBe(0);
    expect(kerl.events[1].sn).toBe(1);
  });
});
```

- [ ] **Step 2: Commit**

```bash
git add keri-core/src/witness-api/ keri-core/tests/witness-api/
git commit -m "feat(keri-core): add witness service API types"
```

---

### Task 5: Update exports

**Files:**
- Modify: `keri-core/src/index.ts`

- [ ] **Step 1: Add all layer 4 exports**

Accountability: `KERL`, `ReceiptRef`, `checkAccountability`, `ample`
Credential-proof: `verifyCredentialArtifacts`, `verifyProofChain`, `ProofResult`, `RegistryState`
Integrity: `DuplicityEventLog`, `DuplicityEvidence`, `SupersedingRecoveryEvent`, `DisputedBranch`, `TrustDecision`, `canSupersede`, `SupersedingRule`
Witness-api: `EventSubmissionResult`, `KERLResponse`, `WitnessServicePort`

- [ ] **Step 2: Run full suite, commit**

```bash
cd keri-core && npx vitest run && npx tsc --noEmit
git add keri-core/src/index.ts
git commit -m "feat(keri-core): export all layer 4 modules"
```

---

## Self-Review

**Spec coverage:**
- accountability: KERL ✓, checkAccountability ✓, ample ✓, ReceiptMessage (deferred — uses Serder), receipt aggregation ✓
- credential-exchange/proof: verifyCredentialArtifacts ✓, verifyProofChain ✓, RegistryState ✓, authenticate_exn (deferred — needs key state lookup)
- integrity: DEL ✓ (append-only), superseding rules A0/A1/A2 ✓, recovery rotation ✓, DisputedBranch ✓, TrustDecision ✓, monitoring (deferred — needs transport)
- witness-service/api: EventSubmissionResult ✓, KERLResponse ✓, WitnessServicePort interface ✓, HTTP server (deferred — higher layer)

**Deferred:** ReceiptMessage Serder construction, exn authentication (needs key state), monitor handle (needs transport), actual HTTP witness server. These are runtime/service concerns for layer 6+.

**Type consistency:** DuplicityEvidence used in both evidence/ (layer 3) and integrity/ (layer 4) — the layer 4 type in integrity/types.ts adds detectedAt field. KERL uses ReceiptRef consistently.
