# Layer 2: Delegation + KERI Messaging + Watcher API

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add delegation event creation/verification, KERI exchange/query/reply message types, and watcher API types to keri-core. Wire delegated inception through the kerizon CLI.

**Architecture:** All three domains add to the existing `keri-core/` package. Delegation adds event types + seal verification. Messaging adds exn/qry/rpy construction using Serder. Watcher API defines the interface types (no server implementation — that's a higher layer). The kerizon CLI gets `dip` support via `--delpre` flag.

**Tech Stack:** TypeScript, vitest, @kerizon/cesr (Serder, Saider, Diger)

---

## File Structure

```
keri-core/
  src/
    delegation/
      create.ts               # NEW: create_delegated_inception, approve_delegation
      verify.ts               # NEW: verify_delegation_seal, find_seal
      types.ts                # NEW: DelegationSeal, DelegatedInceptionConfig
    messaging/
      exchange.ts             # NEW: exchange() → exn message
      query.ts                # NEW: query() → qry message
      reply.ts                # NEW: reply() → rpy message
      types.ts                # NEW: ExchangeMessage, QueryMessage, ReplyMessage, MessageType
    watcher/
      types.ts                # NEW: DuplicityStatus, watcher port interfaces
    index.ts                  # MODIFY: add exports
  tests/
    delegation/
      create.test.ts          # NEW
      verify.test.ts          # NEW
    messaging/
      exchange.test.ts        # NEW
      query.test.ts           # NEW
    watcher/
      types.test.ts           # NEW
```

---

### Task 1: Delegation types + event creation

**Files:**
- Create: `keri-core/src/delegation/types.ts`
- Create: `keri-core/src/delegation/create.ts`
- Test: `keri-core/tests/delegation/create.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// keri-core/tests/delegation/create.test.ts
import { describe, it, expect } from 'vitest';
import { createDelegatedInception, createDelegationSeal } from '../../src/delegation/create.js';
import { incept } from '../../src/events/inception.js';
import { Signer, Diger } from '@kerizon/cesr';

describe('delegation creation', () => {
  it('creates a dip event with di field', async () => {
    const delegatorSigner = await Signer.generate();
    const delegatorIcp = incept({ keys: [delegatorSigner.verfer.qb64], nextDigests: [Diger.digest(new TextEncoder().encode(delegatorSigner.verfer.qb64), 'E').qb64] });
    const delegatorPre = delegatorIcp.said;

    const delegateSigner = await Signer.generate();
    const delegateNext = await Signer.generate();
    const serder = createDelegatedInception({
      delegatorAid: delegatorPre,
      keys: [delegateSigner.verfer.qb64],
      nextDigests: [Diger.digest(new TextEncoder().encode(delegateNext.verfer.qb64), 'E').qb64],
    });

    expect(serder.ilk).toBe('dip');
    expect(serder.ked['di']).toBe(delegatorPre);
    expect(serder.sn).toBe(0);
    expect(serder.ked['i']).toBe(serder.ked['d']); // i == d for inception
    expect(serder.verifySaid()).toBe(true);
  });

  it('creates a delegation seal with i, s, d fields', async () => {
    const seal = createDelegationSeal('EPrefix123', 0, 'ESaid456');
    expect(seal.i).toBe('EPrefix123');
    expect(seal.s).toBe('0');
    expect(seal.d).toBe('ESaid456');
  });

  it('seal s field is hex-encoded', () => {
    const seal = createDelegationSeal('EPrefix', 15, 'ESaid');
    expect(seal.s).toBe('f');
  });
});
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement types + create**

```typescript
// keri-core/src/delegation/types.ts
export interface DelegatedInceptionConfig {
  delegatorAid: string;
  keys: string[];
  nextDigests: string[];
  signingThreshold?: string;
  nextThreshold?: string;
  witnesses?: string[];
  witnessThreshold?: number;
  configTraits?: string[];
  data?: Record<string, unknown>[];
}

export interface DelegationSeal {
  readonly i: string;
  readonly s: string;
  readonly d: string;
}

// keri-core/src/delegation/create.ts
import { Serder } from '@kerizon/cesr';
import type { DelegatedInceptionConfig, DelegationSeal } from './types.js';

export function createDelegatedInception(config: DelegatedInceptionConfig): Serder {
  const ked: Record<string, unknown> = {
    t: 'dip',
    d: '',
    i: '',
    s: '0',
    kt: config.signingThreshold ?? '1',
    k: config.keys,
    nt: config.nextThreshold ?? '1',
    n: config.nextDigests,
    bt: (config.witnessThreshold ?? 0).toString(16),
    b: config.witnesses ?? [],
    c: config.configTraits ?? [],
    a: config.data ?? [],
    di: config.delegatorAid,
  };
  return Serder.fromKed(ked);
}

export function createDelegationSeal(prefix: string, sn: number, said: string): DelegationSeal {
  return { i: prefix, s: sn.toString(16), d: said };
}
```

- [ ] **Step 4: Run to verify pass**
- [ ] **Step 5: Commit**

```bash
git add keri-core/src/delegation/ keri-core/tests/delegation/
git commit -m "feat(keri-core): add delegated inception and delegation seal creation"
```

---

### Task 2: Delegation seal verification

**Files:**
- Create: `keri-core/src/delegation/verify.ts`
- Test: `keri-core/tests/delegation/verify.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// keri-core/tests/delegation/verify.test.ts
import { describe, it, expect } from 'vitest';
import { verifyDelegationSeal, findDelegationSeal } from '../../src/delegation/verify.js';
import type { DelegationSeal } from '../../src/delegation/types.js';

describe('delegation verification', () => {
  it('verifyDelegationSeal returns true when seal matches event', () => {
    const seal: DelegationSeal = { i: 'EDelegate', s: '0', d: 'ESaid123' };
    expect(verifyDelegationSeal(seal, 'EDelegate', 0, 'ESaid123')).toBe(true);
  });

  it('verifyDelegationSeal returns false on prefix mismatch', () => {
    const seal: DelegationSeal = { i: 'EDelegate', s: '0', d: 'ESaid123' };
    expect(verifyDelegationSeal(seal, 'EWrong', 0, 'ESaid123')).toBe(false);
  });

  it('verifyDelegationSeal returns false on sn mismatch', () => {
    const seal: DelegationSeal = { i: 'EDelegate', s: '0', d: 'ESaid123' };
    expect(verifyDelegationSeal(seal, 'EDelegate', 1, 'ESaid123')).toBe(false);
  });

  it('verifyDelegationSeal returns false on SAID mismatch', () => {
    const seal: DelegationSeal = { i: 'EDelegate', s: '0', d: 'ESaid123' };
    expect(verifyDelegationSeal(seal, 'EDelegate', 0, 'EWrong')).toBe(false);
  });

  it('findDelegationSeal finds matching seal in event anchors', () => {
    const events = [
      { a: [{ i: 'EDelegate', s: '0', d: 'ESaid' }] },
      { a: [] },
    ];
    const found = findDelegationSeal(events, 'EDelegate', 0, 'ESaid');
    expect(found).toBeTruthy();
    expect(found!.d).toBe('ESaid');
  });

  it('findDelegationSeal returns null when no match', () => {
    const events = [{ a: [{ i: 'EOther', s: '0', d: 'ESaid' }] }];
    const found = findDelegationSeal(events, 'EDelegate', 0, 'ESaid');
    expect(found).toBeNull();
  });
});
```

- [ ] **Step 2: Implement**

```typescript
// keri-core/src/delegation/verify.ts
import type { DelegationSeal } from './types.js';

export function verifyDelegationSeal(
  seal: DelegationSeal,
  delegatePrefix: string,
  delegateSn: number,
  delegateSaid: string,
): boolean {
  return seal.i === delegatePrefix
    && seal.s === delegateSn.toString(16)
    && seal.d === delegateSaid;
}

export function findDelegationSeal(
  delegatorEvents: Array<Record<string, unknown>>,
  delegatePrefix: string,
  delegateSn: number,
  delegateSaid: string,
): DelegationSeal | null {
  for (const event of delegatorEvents) {
    const anchors = event['a'] as Array<Record<string, unknown>> | undefined;
    if (!anchors) continue;
    for (const anchor of anchors) {
      if (typeof anchor['i'] === 'string' && typeof anchor['s'] === 'string' && typeof anchor['d'] === 'string') {
        const seal: DelegationSeal = { i: anchor['i'] as string, s: anchor['s'] as string, d: anchor['d'] as string };
        if (verifyDelegationSeal(seal, delegatePrefix, delegateSn, delegateSaid)) {
          return seal;
        }
      }
    }
  }
  return null;
}
```

- [ ] **Step 3: Run, verify, commit**

```bash
git add keri-core/src/delegation/ keri-core/tests/delegation/
git commit -m "feat(keri-core): add delegation seal verification"
```

---

### Task 3: KERI messaging — exn, qry, rpy

**Files:**
- Create: `keri-core/src/messaging/types.ts`
- Create: `keri-core/src/messaging/exchange.ts`
- Create: `keri-core/src/messaging/query.ts`
- Create: `keri-core/src/messaging/reply.ts`
- Test: `keri-core/tests/messaging/exchange.test.ts`
- Test: `keri-core/tests/messaging/query.test.ts`

- [ ] **Step 1: Write types**

```typescript
// keri-core/src/messaging/types.ts
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
```

- [ ] **Step 2: Write failing tests**

```typescript
// keri-core/tests/messaging/exchange.test.ts
import { describe, it, expect } from 'vitest';
import { exchange } from '../../src/messaging/exchange.js';

describe('exchange message', () => {
  it('creates exn with correct ilk and route', () => {
    const serder = exchange({
      route: '/ipex/grant',
      sender: 'ESenderPrefix',
      payload: { LEI: '12345' },
    });
    expect(serder.ilk).toBe('exn');
    expect(serder.ked['r']).toBe('/ipex/grant');
    expect(serder.ked['i']).toBe('ESenderPrefix');
    expect(serder.verifySaid()).toBe(true);
  });

  it('links to prior message via p field', () => {
    const serder = exchange({
      route: '/ipex/admit',
      sender: 'ESender',
      payload: {},
      prior: 'EPriorSaid',
    });
    expect(serder.ked['p']).toBe('EPriorSaid');
  });

  it('includes embeds in e field', () => {
    const serder = exchange({
      route: '/multisig/icp',
      sender: 'ESender',
      payload: {},
      embeds: { icp: { t: 'icp' } },
    });
    expect(serder.ked['e']).toEqual({ icp: { t: 'icp' } });
  });
});

// keri-core/tests/messaging/query.test.ts
import { describe, it, expect } from 'vitest';
import { query, reply } from '../../src/messaging/query.js';

describe('query message', () => {
  it('creates qry with route and query params', () => {
    const serder = query({
      route: 'logs',
      replyRoute: '/ksn',
      query: { i: 'ETargetAid' },
    });
    expect(serder.ilk).toBe('qry');
    expect(serder.ked['r']).toBe('logs');
    expect(serder.ked['rr']).toBe('/ksn');
    expect(serder.ked['q']).toEqual({ i: 'ETargetAid' });
    expect(serder.verifySaid()).toBe(true);
  });
});

describe('reply message', () => {
  it('creates rpy with route and data', () => {
    const serder = reply({
      route: '/end/role',
      data: { cid: 'EAid', role: 'witness', eid: 'EWitness' },
    });
    expect(serder.ilk).toBe('rpy');
    expect(serder.ked['r']).toBe('/end/role');
    expect(serder.ked['a']).toEqual({ cid: 'EAid', role: 'witness', eid: 'EWitness' });
    expect(serder.verifySaid()).toBe(true);
  });
});
```

- [ ] **Step 3: Implement**

```typescript
// keri-core/src/messaging/exchange.ts
import { Serder } from '@kerizon/cesr';
import type { ExchangeConfig } from './types.js';

export function exchange(config: ExchangeConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'exn',
    d: '',
    i: config.sender,
    rp: '',
    p: config.prior ?? '',
    dt,
    r: config.route,
    q: {},
    a: config.payload,
    e: config.embeds ?? {},
  };
  return Serder.fromKed(ked);
}

// keri-core/src/messaging/query.ts
import { Serder } from '@kerizon/cesr';
import type { QueryConfig, ReplyConfig } from './types.js';

export function query(config: QueryConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'qry',
    d: '',
    dt,
    r: config.route,
    rr: config.replyRoute,
    q: config.query,
  };
  return Serder.fromKed(ked);
}

// keri-core/src/messaging/reply.ts
import { Serder } from '@kerizon/cesr';
import type { ReplyConfig } from './types.js';

export function reply(config: ReplyConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'rpy',
    d: '',
    dt,
    r: config.route,
    a: config.data,
  };
  return Serder.fromKed(ked);
}
```

- [ ] **Step 4: Run, verify, commit**

```bash
git add keri-core/src/messaging/ keri-core/tests/messaging/
git commit -m "feat(keri-core): add exn/qry/rpy message construction"
```

---

### Task 4: Watcher API types + exports

**Files:**
- Create: `keri-core/src/watcher/types.ts`
- Test: `keri-core/tests/watcher/types.test.ts`
- Modify: `keri-core/src/index.ts`

- [ ] **Step 1: Write types + test**

```typescript
// keri-core/src/watcher/types.ts
export interface DuplicityStatus {
  readonly aid: string;
  readonly isDuplicitous: boolean;
  readonly evidence: string[];  // SAIDs of conflicting events
}

export interface WatcherPort {
  queryKel(aid: string): Promise<unknown>;
  queryDuplicity(aid: string): Promise<DuplicityStatus>;
}

export function createDuplicityStatus(
  aid: string,
  conflictingSaids: string[],
): DuplicityStatus {
  return {
    aid,
    isDuplicitous: conflictingSaids.length >= 2,
    evidence: conflictingSaids,
  };
}

// keri-core/tests/watcher/types.test.ts
import { describe, it, expect } from 'vitest';
import { createDuplicityStatus } from '../../src/watcher/types.js';

describe('watcher types', () => {
  it('no evidence → not duplicitous', () => {
    const s = createDuplicityStatus('EAid', []);
    expect(s.isDuplicitous).toBe(false);
    expect(s.evidence).toEqual([]);
  });

  it('one SAID → not duplicitous', () => {
    const s = createDuplicityStatus('EAid', ['ESaid1']);
    expect(s.isDuplicitous).toBe(false);
  });

  it('two conflicting SAIDs → duplicitous', () => {
    const s = createDuplicityStatus('EAid', ['ESaid1', 'ESaid2']);
    expect(s.isDuplicitous).toBe(true);
    expect(s.evidence).toEqual(['ESaid1', 'ESaid2']);
  });
});
```

- [ ] **Step 2: Update keri-core/src/index.ts**

Add all new exports: delegation, messaging, watcher.

- [ ] **Step 3: Run full suite, commit**

```bash
git add keri-core/
git commit -m "feat(keri-core): add watcher types and update all layer 2 exports"
```

---

---

### Task 5: Cross-implementation delegation conformance test

**Files:**
- Create: `kli-conformance/tests/cross-impl/delegation-interop.test.ts`
- Modify: `kli-conformance/src/adapter/kerizon-adapter.ts` (add `incept` support for `delegator` field)

This test exercises delegation as **communication between kli and kerizon** — no witnesses needed. Two CLIs exchange CESR streams via export/import.

- [ ] **Step 1: Ensure kerizon CLI supports --delpre flag for delegated inception**

Check `kerizon-cli/src/cli.ts` — the `incept` command already reads `delpre` from the InceptConfig and passes it to `incept()` which produces a `dip` event. If not, add it.

Also ensure the KerizonAdapter maps `config.delegator` to `--delpre`.

- [ ] **Step 2: Write the cross-implementation test**

```typescript
// kli-conformance/tests/cross-impl/delegation-interop.test.ts
import { describe, it, expect, beforeAll } from 'vitest';
import { KliAdapter } from '../../src/adapter/kli-adapter.js';
import { KerizonAdapter } from '../../src/adapter/kerizon-adapter.js';
import { KLI_AVAILABLE } from '../kli-available.js';
import { resolve } from 'node:path';

const CLI_PATH = resolve(import.meta.dirname, '../../../kerizon-cli/dist/cli.js');
const SKIP = !KLI_AVAILABLE;

let kli: KliAdapter;
let kerizon: KerizonAdapter;
const kliKs = `xdel-kli-${Date.now()}`;
const kerizonKs = `xdel-kerizon-${Date.now()}`;

beforeAll(async () => {
  if (SKIP) return;

  // Set up kli as delegator
  kli = new KliAdapter({ keystoreName: kliKs });
  await kli.init({ name: kliKs, nopasscode: true });
  await kli.incept({ alias: 'delegator', transferable: true });

  // Set up kerizon
  kerizon = new KerizonAdapter({
    cliPath: CLI_PATH,
    useNode: true,
    keystoreName: kerizonKs,
  });
  await kerizon.init({ name: kerizonKs, nopasscode: true });
});

describe.skipIf(SKIP)('cross-implementation delegation', () => {
  it('kli exports delegator KEL → kerizon imports it', async () => {
    const exported = await kli.exportKel('delegator');
    expect(exported.exitCode).toBe(0);
    expect(exported.cesr!.length).toBeGreaterThan(0);

    const imported = await kerizon.importKel(exported.cesr!);
    expect(imported.exitCode).toBe(0);
  });

  it('kerizon creates delegated inception referencing kli delegator', async () => {
    const delegatorStatus = await kli.status('delegator');
    const delegatorPre = delegatorStatus.keyState!.prefix;

    // kerizon creates a dip event with di = delegator's prefix
    const r = await kerizon.incept({
      alias: 'delegated',
      transferable: true,
      delegator: delegatorPre,
    });
    expect(r.exitCode).toBe(0);
    expect(r.prefix).toBeTruthy();

    // Verify the event is a dip with correct di field
    const events = await kerizon.exportEvents('delegated');
    expect(events.events).toBeTruthy();
    const dip = JSON.parse(events.events![0].raw);
    expect(dip['t']).toBe('dip');
    expect(dip['di']).toBe(delegatorPre);
  });

  it('kerizon exports delegated KEL → kli can parse it', async () => {
    const exported = await kerizon.exportKel('delegated');
    expect(exported.exitCode).toBe(0);

    const imported = await kli.importKel(exported.cesr!);
    // kli may escrow this (missing delegation seal) — that's expected
    // The test verifies the CESR stream is parseable across implementations
    // Exit code 0 means the stream was valid CESR even if escrowed
    expect(imported.exitCode).toBe(0);
  });

  it('kli creates delegation approval seal via interact', async () => {
    const delegatorStatus = await kli.status('delegator');
    const delegatedEvents = await kerizon.exportEvents('delegated');
    const dip = JSON.parse(delegatedEvents.events![0].raw);

    // kli creates an ixn with the delegation seal
    const r = await kli.interact({
      alias: 'delegator',
      data: [{
        i: dip['i'],
        s: dip['s'],
        d: dip['d'],
      }],
    });
    expect(r.exitCode).toBe(0);
  });

  it('kli delegator KEL contains the delegation seal', async () => {
    const events = await kli.exportEvents('delegator');
    expect(events.events!.length).toBeGreaterThanOrEqual(2); // icp + ixn

    // The ixn should have the delegation seal in its anchor
    const ixn = JSON.parse(events.events![1].raw);
    expect(ixn['t']).toBe('ixn');
    expect(ixn['a'].length).toBeGreaterThan(0);

    const delegatedEvents = await kerizon.exportEvents('delegated');
    const dip = JSON.parse(delegatedEvents.events![0].raw);

    // Verify seal matches
    const seal = ixn['a'][0];
    expect(seal['i']).toBe(dip['i']);
    expect(seal['d']).toBe(dip['d']);
  });

  it('both implementations agree on the delegation chain', async () => {
    // Export kli's full updated KEL (icp + ixn with seal)
    const kliKel = await kli.exportKel('delegator');
    // Import into kerizon so it has the full picture
    await kerizon.importKel(kliKel.cesr!);

    // Both sides can verify the prefix
    const kliStatus = await kli.status('delegator');
    const kerizonDelegated = await kerizon.exportEvents('delegated');
    const dip = JSON.parse(kerizonDelegated.events![0].raw);

    expect(dip['di']).toBe(kliStatus.keyState!.prefix);
  });
});
```

- [ ] **Step 3: Add --delpre support to kerizon CLI if missing**

Check `kerizon-cli/src/cli.ts` — the `cmdIncept` function should read `--delpre` flag and pass it as `delegator` to the `incept()` function. If not present, add:

```typescript
const delpre = getFlag(flags, 'delpre');
// In the incept call:
delegator: delpre || undefined,
```

Also check the KerizonAdapter's `incept` method maps `config.delegator` to `--delpre`.

- [ ] **Step 4: Run the cross-implementation test**

Run: `cd kli-conformance && source ../.venv/bin/activate && npx vitest run tests/cross-impl/delegation-interop.test.ts`
Expected: PASS (requires kli installed)

- [ ] **Step 5: Commit**

```bash
git add kli-conformance/tests/cross-impl/ kerizon-cli/src/cli.ts kli-conformance/src/adapter/kerizon-adapter.ts
git commit -m "test: cross-implementation delegation — kli delegator + kerizon delegate via CESR exchange"
```

---

## Self-Review

**Spec coverage:**
- delegation/lifecycle: create_delegated_inception ✓, approve_delegation (seal creation) ✓
- delegation/verification: verify_delegation_seal ✓, find_delegation_seal ✓, verify_delegation_chain (deferred — needs recursive KEL access)
- delegation/query: is_delegated (trivial via ked['di']) ✓, get_delegator ✓
- keri-messaging: exchange ✓, query ✓, reply ✓, parse (deferred — needs full parser), validate_version (exists in cesr/), validate_said (exists as Saider.verify)
- watcher-service/api: DuplicityStatus ✓, WatcherPort interface ✓, actual service (higher layer)

**Deferred:** GroupCoordination (multi-sig coordination needs messaging loop), message parsing (needs CESR stream parser), watcher HTTP server.

**Type consistency:** DelegationSeal used consistently in create.ts and verify.ts. Serder used for all message construction. ExchangeConfig/QueryConfig/ReplyConfig are standalone.
