# Layer 5: Discovery + Identity Root

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OOBI/endpoint discovery types with BADA acceptance policy, and the identity root orchestrator with event processing pipeline and escrow cascade.

**Architecture:** Both domains add to `keri-core/`. Discovery adds OOBI types, endpoint resolution model, and BADA policy. Identity root adds `processEvent` pipeline that ties together validation (layer 0), escrow routing, and state updates. No HTTP servers — just the domain logic and types.

**Tech Stack:** TypeScript, vitest, @kerizon/cesr

---

### Task 1: Discovery — OOBI types + BADA policy

**Files:**
- Create: `keri-core/src/discovery/types.ts`
- Create: `keri-core/src/discovery/bada.ts`
- Create: `keri-core/src/discovery/oobi.ts`
- Test: `keri-core/tests/discovery/oobi.test.ts`
- Test: `keri-core/tests/discovery/bada.test.ts`

Types: OOBI (4 variants), EndRole, LocationScheme, ServiceEndpoint, ResolvedEndpoint, BadaRecord.

BADA: `shouldAccept(existing, incoming)` — signed+anchored > signed > unsigned; newer datetime wins within same tier.

OOBI: `parseOobi(url)` — extracts AID, role, eid from URL path; `formatOobi(parts)` — builds URL.

Tests: parse/format round-trip, BADA acceptance ordering, reject stale, accept newer.

---

### Task 2: Identity root — Escrow types + cascade

**Files:**
- Create: `keri-core/src/identity/escrow.ts`
- Create: `keri-core/src/identity/types.ts`
- Test: `keri-core/tests/identity/escrow.test.ts`

EscrowType enum (OOE, PSE, PWE, PDE, LDE, Misfit), EscrowedEvent type, EscrowStore class (add, drain by aid+sn, timeout sweep).

Tests: add to escrow, drain matching events, timeout prunes old entries, correct escrow type assignment.

---

### Task 3: Identity root — processEvent pipeline

**Files:**
- Create: `keri-core/src/identity/process.ts`
- Test: `keri-core/tests/identity/process.test.ts`

`processEvent(event, keyState?, opts?)` — the core pipeline:
1. If unknown prefix + inception → create Kever, return Accepted
2. If unknown prefix + non-inception → return Escrowed(OOE)
3. If sn > expected → return Escrowed(OOE)
4. If sn < expected + same SAID → return Duplicate
5. If sn < expected + different SAID → return Escrowed(LDE)
6. If sn == expected → validate, apply to Kever, return Accepted

Tests: inception accepted, out-of-order escrowed, duplicate ignored, fork detected, rotation applied, interaction applied, EO rejects ixn.

---

### Task 4: Update exports + cross-impl test

**Files:**
- Modify: `keri-core/src/index.ts`
- Create: `kli-conformance/tests/cross-impl/oobi-format-interop.test.ts`

Exports + a cross-impl test verifying OOBI URL format matches between implementations.
