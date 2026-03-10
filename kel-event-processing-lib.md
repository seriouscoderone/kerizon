# KEL Event Processing Library Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification for a standalone KEL (Key Event Log) event processing library, suitable for generating conformant implementations in any language.
**Normative basis:** [KERI Specification](https://trustoverip.github.io/kswg-keri-specification/), [CESR Specification](https://trustoverip.github.io/kswg-cesr-specification/)
**Cross-checked against:** keripy reference implementation (`src/keri/core/eventing.py`, `src/keri/db/basing.py`, `src/keri/kering.py`, `src/keri/recording.py`)

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Terminology](#2-terminology)
3. [Module Structure](#3-module-structure)
4. [Types and Constants](#4-types-and-constants)
5. [Error Hierarchy](#5-error-hierarchy)
6. [Builder and View Architecture](#6-builder-and-view-architecture)
7. [Signature Verification](#7-signature-verification)
8. [IdentifierState — Aggregate Root](#8-identifierstate--aggregate-root)
9. [EventProcessor — Domain Service](#9-eventprocessor--domain-service)
10. [EventRepository — Repository Interface](#10-eventrepository--repository-interface)
11. [Escrow System](#11-escrow-system)
12. [Domain Events](#12-domain-events)
13. [Invariant Contract](#13-invariant-contract)
14. [Configuration](#14-configuration)
15. [Test Specification](#15-test-specification)
- [Appendix A: Usage Examples](#appendix-a-usage-examples)
- [Appendix B: DDD Name Mapping](#appendix-b-ddd-name-mapping)
- [Appendix C: Wire-Format Field Reference](#appendix-c-wire-format-field-reference)

---

## 1. Purpose and Scope

This specification defines the public API, invariants, and behavioral contract of a standalone KEL event processing library. An implementation of this spec processes KERI Key Event Log entries — inception, rotation, interaction, delegated inception, delegated rotation, and receipt messages — maintaining identifier key state and enforcing all cryptographic and structural invariants defined by the KERI protocol.

### In scope

- **IdentifierState** (aggregate root): one instance per AID, encapsulates key state and invariant enforcement
- **EventProcessor** (domain service): stateless orchestrator dispatching events and managing escrows
- **Event builders**: typed builder pattern wrapping wire-format field maps for inception, rotation, interaction, delegated variants, and receipts
- **Seal builders**: typed constructors for EventSeal, DigestSeal, RootSeal, SourceSeal, LastEstSeal, BackerSeal, KindSeal
- **SignedEvent composition**: two-step build-then-sign pattern
- **KeyState view**: read-only domain-language access to stored/received state
- **PendingEvent view**: escrow query interface
- **Signature verification**: controller, witness, and delegation signature validation
- **Escrow system**: 9 escrow types with entry, storage, resolution, and timeout
- **Receipt processing**: non-transferable, witness, and transferable receipts
- **Domain events**: typed output signals for infrastructure consumption
- **EventRepository**: abstract persistence boundary (~40 methods)

### Out of scope

This specification does **not** cover:

- Key management (key generation, storage, salting, encryption)
- Networking (transport, parsing streams, message framing)
- TEL (Transaction Event Log) or ACDC (Authentic Chained Data Containers)
- Exchange protocol (`exn` messages)
- OOBI (Out-of-Band Introduction) resolution
- Reply messages (`rpy`, `qry`)
- Stream parsing (CESR stream extraction)
- Group multisig coordination (the coordination protocol; individual group member events ARE processed)
- Framework dependencies (no hio, falcon, asyncio, or equivalent)

### Shared kernel (assumed given)

CESR primitives are a shared kernel dependency, not redefined here:

- **Prefixer** — qualified AID prefix
- **Diger** — qualified digest
- **Verfer** — qualified public verification key
- **Siger** — indexed signature
- **Cigar** — unindexed signature
- **Tholder** — threshold holder (simple integer or weighted fractional)
- **Serder** — self-addressing data serializer/deserializer
- **Number** — qualified sequence number
- **Dater** — qualified ISO-8601 datetime
- **Saider** — SAID (Self-Addressing Identifier) computation

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **AID** | Autonomic Identifier — a self-certifying, self-managing cryptographic identifier |
| **KEL** | Key Event Log — append-only log of key events for a single AID |
| **SAID** | Self-Addressing Identifier — content-addressable digest that serves as the identifier of the content itself |
| **TOAD** | Threshold of Accountable Duplicity — minimum number of witness receipts required |
| **Pre-rotation** | Commitment to next rotation keys via cryptographic digests in the current establishment event |
| **Establishment event** | An event that changes key state (inception, rotation, delegated variants) |
| **Non-establishment event** | An event that does not change key state (interaction) |
| **Escrow** | Temporary storage for events that cannot yet be fully validated |
| **Domain event** | A typed output signal produced by the library for infrastructure consumption |
| **IdentifierState** | The aggregate root maintaining one AID's key state and enforcing invariants |
| **EventProcessor** | The domain service orchestrating event dispatch, receipt processing, and escrow resolution |
| **EventRepository** | The abstract persistence boundary (repository interface) |
| **KeyStateSnapshot** | A serializable value object projecting the full key state of an identifier |
| **EventProvenance** | A value object marking whether an event originated locally or remotely |
| **EstablishmentLocator** | A value object pairing (sequence number, digest) to locate the last establishment event |
| **EstablishmentDetail** | A value object recording detail of the last establishment event (sn, dig, cuts, adds) |
| **DomainEventBus** | A FIFO queue of typed domain events produced by the library |

---

## 3. Module Structure

```
kel/
    types                — Value objects: KeyStateSnapshot, EventProvenance,
                           EstablishmentLocator, EstablishmentDetail,
                           ilk constants, trait constants, seal types
    errors               — Error hierarchy (10 domain error types)
    config               — ProcessorConfig, EscrowTimeouts
    builders/
        inception        — InceptionBuilder, DelegatedInceptionBuilder
        rotation         — RotationBuilder, DelegatedRotationBuilder
        interaction      — InteractionBuilder
        receipt          — ReceiptBuilder
        seals            — EventSeal, DigestSeal, RootSeal, SourceSeal,
                           LastEstSeal, BackerSeal, KindSeal
        signed_event     — SignedEvent composition (event + signatures)
    views/
        key_state        — KeyState read-only conceptual view
        pending_event    — PendingEvent escrow view, EscrowReason enum
    verification         — verifySigs, validateSigs, ampleSufficient
    identifier_state     — IdentifierState aggregate root
    event_processor      — EventProcessor domain service
    domain_events        — Typed domain event definitions + DomainEventBus
    repository/
        interface        — EventRepository trait (abstract persistence)
        keys             — digestKey/sequenceKey construction helpers
        memory           — InMemoryEventRepository (for testing)
```

**Dependency rules:**

- `builders/`, `views/`, `types`, `errors`, `config` have **zero** internal dependencies beyond each other
- `verification` depends on `types` and CESR shared kernel only
- `identifier_state` depends on `types`, `errors`, `verification`, `repository/interface`
- `event_processor` depends on `identifier_state`, `domain_events`, `repository/interface`, `config`
- `repository/memory` implements `repository/interface` — used for testing only
- **No circular dependencies** exist in this module graph

---

## 4. Types and Constants

### 4.1 KeyStateSnapshot

A serializable value object projecting the complete key state of an identifier at a point in time.

Cross-ref: `recording.py:77` (`KeyStateRecord`)

| Field | Type | Description |
|-------|------|-------------|
| `vn` | list[int] | Version (major, minor) |
| `i` | str | Identifier prefix (AID) |
| `s` | str | Sequence number (hex-encoded) |
| `p` | str | Prior event SAID |
| `d` | str | Current event SAID |
| `f` | str | First-seen ordinal (hex-encoded) |
| `dt` | str | First-seen ISO-8601 datetime |
| `et` | str | Event type ilk of current event |
| `kt` | str or list | Signing threshold |
| `k` | list[str] | Current signing keys (Verfer qb64) |
| `nt` | str or list | Next key threshold |
| `n` | list[str] | Next key digests (Diger qb64) |
| `bt` | str | Witness threshold (TOAD) |
| `b` | list[str] | Current witness prefixes |
| `c` | list[str] | Configuration traits |
| `ee` | EstablishmentDetail | Last establishment event detail |
| `di` | str | Delegator prefix (empty string if not delegated) |

### 4.2 EstablishmentDetail

Cross-ref: `recording.py:59` (`StateEERecord`)

| Field | Type | Description |
|-------|------|-------------|
| `s` | str | Sequence number of last establishment event (hex) |
| `d` | str | SAID of last establishment event |
| `br` | list[str] | Witness prefixes removed (cuts) |
| `ba` | list[str] | Witness prefixes added |

### 4.3 EstablishmentLocator

Cross-ref: `eventing.py:51` (`LastEstLoc`)

| Field | Type | Description |
|-------|------|-------------|
| `sn` | int | Sequence number of last establishment event |
| `digest` | str | SAID of last establishment event |

### 4.4 EventProvenance

Cross-ref: `recording.py:133` (`EventSourceRecord`)

| Field | Type | Description |
|-------|------|-------------|
| `local` | bool | `true` if event originated from a locally-controlled source; `false` if remote |

### 4.5 Event Ilks

Constants identifying event types.

Cross-ref: `kering.py:351` (`Ilkage`, `Ilks`)

| Constant | Wire Value | Description |
|----------|-----------|-------------|
| `Inception` | `"icp"` | Inception event |
| `Rotation` | `"rot"` | Rotation event |
| `Interaction` | `"ixn"` | Interaction event |
| `DelegatedInception` | `"dip"` | Delegated inception event |
| `DelegatedRotation` | `"drt"` | Delegated rotation event |
| `Receipt` | `"rct"` | Receipt message |

### 4.6 Configuration Traits

Cross-ref: `kering.py:382` (`TraitCodex`, `TraitDex`)

| Constant | Wire Value | Description |
|----------|-----------|-------------|
| `EstablishmentOnly` | `"EO"` | Identifier only allows establishment events (no interactions) |
| `DoNotDelegate` | `"DND"` | Identifier cannot serve as delegator |

---

## 5. Error Hierarchy

Each error type serves as the **escrow routing mechanism**. When validation fails, the specific error type determines which escrow receives the event. All errors derive from a common `ValidationError` base.

Cross-ref: `kering.py:609` (`ValidationError` and subclasses)

| Error Type | Target Escrow | Trigger Condition | Cross-ref |
|------------|---------------|-------------------|-----------|
| `OutOfOrderError` | OOE | Prior event missing from log | `kering.py:674` |
| `InsufficientSignaturesError` | PSE | Controller signatures below signing threshold | `kering.py:642` |
| `InsufficientWitnessesError` | PWE | Witness signatures below TOAD | `kering.py:658` |
| `MissingDelegationError` | PDE | Delegation seal not found in delegator's KEL | `kering.py:666` |
| `PendingDelegationApprovalError` | delegable | Local delegator has not yet anchored approval seal | `kering.py:802` |
| `ProvenanceMismatchError` | MFE | Remote-sourced event for locally-controlled identifier | `kering.py:794` |
| `UnverifiedWitnessReceiptError` | UWE | Witness receipt arrived before the receipted event | `kering.py:690` |
| `UnverifiedReceiptError` | URE | Non-transferable receipt arrived before the receipted event | `kering.py:698` |
| `UnverifiedTransferableReceiptError` | VRE | Transferable receipt arrived before the receipted event | `kering.py:706` |
| `DuplicitousEventError` | LDE | Different event (different SAID) at same (prefix, sequence number) | `kering.py:682` |

### Error flow

```
ingestEvent(event, sigs, ...)
    │
    ├── validation succeeds → commitEvent → produce domain event
    │
    └── validation raises error
            │
            ├── OutOfOrderError       → store in OOE escrow
            ├── InsufficientSigsError → store in PSE escrow
            ├── InsufficientWitsError → store in PWE escrow
            ├── MissingDelegation     → store in PDE escrow
            ├── PendingDelegApproval  → store in delegable escrow
            ├── ProvenanceMismatch    → store in MFE escrow
            └── DuplicitousEvent      → store in LDE escrow
```

---

## 6. Builder and View Architecture

### 6.1 Design Principle

KERI MUST NOT be a field manipulation exercise. Wire-format field names (`v`, `t`, `d`, `i`, `s`, `kt`, `k`, `nt`, `n`, `bt`, `b`, `br`, `ba`, `c`, `a`, `di`, `p`) are preserved in the underlying serialized event per the KERI specification. However, the library's primary API surface wraps these in **builders** (for construction) and **views** (for reading) that expose domain concepts and enforce constraints.

This approach reveals hidden domain concepts:

- **"signing authority"** instead of raw `k` + `kt` fields
- **"pre-rotation commitment"** instead of raw `n` + `nt` fields
- **"witness configuration"** instead of raw `b` + `bt` fields
- **"witness rotation"** instead of raw `br` + `ba` fields
- **"establishment traits"** instead of raw `c` field array

Builders are **pure** — no repository access, no side effects. They produce a valid serialized Event on `.build()`.

Cross-ref: `eventing.py:554` (`incept`), `eventing.py:709` (`rotate`), `eventing.py:904` (`interact`)

### 6.2 InceptionBuilder

```
InceptionBuilder
  .signing_keys([key1, key2])             → field k     (Verfer qb64 strings)
  .signing_threshold(n)                   → field kt    (default: ceil(len(k)/2))
  .next_keys([nk1, nk2])                 → field n     (auto-digested: developer
                                                         provides keys, builder
                                                         computes Blake3-256 digests)
  .next_key_threshold(n)                  → field nt    (default: ceil(len(n)/2))
  .witnesses([w1, w2, w3])               → field b     (default: [])
  .witness_threshold(n)                   → field bt    (default: ample(len(b)))
  .establishment_only()                   → field c += "EO"
  .do_not_delegate()                      → field c += "DND"
  .anchored_seals([seal1, seal2])         → field a     (typed seal objects)
  .non_transferable() → NarrowedBuilder   — removes .next_keys(), .witnesses(),
                                            .anchored_seals() at type level
  .build() → Event
```

**Build-time validation:**

1. `signing_keys` MUST be non-empty
2. `signing_threshold` MUST be ≤ len(signing_keys)
3. `next_key_threshold` MUST be ≤ len(next_keys) when next_keys provided
4. `witness_threshold` MUST be ≤ len(witnesses) when witnesses provided
5. No duplicate entries in `witnesses`
6. Non-transferable: `next_keys` MUST be empty, `witnesses` MUST be empty, `anchored_seals` MUST be empty
7. SAID (`d` field) computed over serialized body and injected automatically
8. Prefix (`i` field) derived from self-addressing computation of inception body

**Default thresholds:**

- `signing_threshold`: `ceil(len(k) / 2)`
- `next_key_threshold`: `ceil(len(n) / 2)`
- `witness_threshold`: `ample(len(b))` (BFT optimal, see [Section 7.3](#73-amplesufficient))

### 6.3 RotationBuilder

```
RotationBuilder
  .identifier(prefix)                     → field i
  .previous_event(said)                   → field p
  .sequence_number(sn)                    → field s
  .signing_keys([new_k1])                → field k
  .signing_threshold(n)                   → field kt
  .next_keys([future_k1])                → field n     (auto-digested)
  .next_key_threshold(n)                  → field nt
  .cut_witnesses([w_remove])              → field br
  .add_witnesses([w_add])                 → field ba
  .witness_threshold(n)                   → field bt
  .anchored_seals([seal])                 → field a
  .from_key_state(state) → RotationBuilder  — pre-fills identifier, previous_event,
                                              sequence_number, current witnesses
  .build() → Event
```

**Build-time validation:**

1. `sequence_number` MUST be ≥ 1
2. `previous_event` MUST be provided
3. `identifier` MUST be provided
4. Cuts MUST be a subset of current witnesses (when `from_key_state` used)
5. Adds MUST NOT overlap with current witnesses (when `from_key_state` used)
6. No duplicate entries in cuts or adds
7. Cuts and adds MUST NOT overlap with each other
8. Resulting witness list MUST NOT contain duplicates
9. `witness_threshold` MUST be ≤ resulting witness count
10. Pre-rotation commitment check if KeyState available

### 6.4 InteractionBuilder

```
InteractionBuilder
  .identifier(prefix)                     → field i
  .previous_event(said)                   → field p
  .sequence_number(sn)                    → field s
  .anchored_seals([seal])                 → field a
  .from_key_state(state) → InteractionBuilder
  .build() → Event
```

**Build-time validation:**

1. `sequence_number` MUST be ≥ 1
2. `previous_event` MUST be provided
3. `identifier` MUST be provided

### 6.5 DelegatedInceptionBuilder

Extends InceptionBuilder with one additional method:

```
DelegatedInceptionBuilder
  (inherits all InceptionBuilder methods)
  .delegator(delegator_prefix)            → field di    (REQUIRED, sets ilk to dip)
  .build() → Event
```

The `delegator` field is **required** — build MUST fail if not set.

### 6.6 DelegatedRotationBuilder

Extends RotationBuilder:

```
DelegatedRotationBuilder
  (inherits all RotationBuilder methods)
  — ilk forced to "drt"
  — delegation seal validation on build
  .build() → Event
```

### 6.7 ReceiptBuilder

```
ReceiptBuilder
  .for_event(event) → ReceiptBuilder      — extracts i, s, d from event
  .build() → Receipt
```

The `.for_event()` method extracts the identifier prefix, sequence number, and SAID from the target event to construct the receipt.

### 6.8 Seal Builders

Typed, discoverable constructors for all KERI seal types. Each produces a wire-format field map.

```
EventSeal.of(identifier, sequence_number, digest)   → {i, s, d}
DigestSeal.of(digest)                               → {d}
RootSeal.of(digest)                                 → {rd}
SourceSeal.of(sequence_number, digest)              → {s, d}
LastEstSeal.of(identifier)                          → {i}
BackerSeal.of(backer_prefix, digest)                → {bi, d}
KindSeal.of(type_version, digest)                   → {t, d}
```

Multiple seal types MAY be composed in a single `.anchored_seals([])` call. The `a` field in the resulting event is an ordered list preserving all seal entries.

### 6.9 SignedEvent Composition

Events are built then signed in two explicit steps:

```
event = InceptionBuilder()
    .signing_keys([k1.qb64, k2.qb64])
    .next_keys([n1.qb64, n2.qb64])
    .witnesses([w1, w2, w3])
    .build()

signed = event.sign_with([signer1, signer2])
    — each signer produces a Siger with correct index
    — returns SignedEvent(event, [siger1, siger2])
```

A `SignedEvent` is a composition of:

| Component | Type | Description |
|-----------|------|-------------|
| `event` | Event (Serder) | The serialized event body |
| `signatures` | list[Siger] | Indexed controller signatures |
| `witness_signatures` | list[Siger] | Indexed witness signatures (optional) |
| `receipt_couples` | list[(Prefixer, Cigar)] | Non-transferable receipt couples (optional) |
| `receipt_quadruples` | list[(Prefixer, Number, Diger, Siger)] | Transferable receipt quadruples (optional) |

**Fluent chain from KeyState:**

```
signed = key_state
    .prepare_rotation()
    .signing_keys([new_k1.qb64])
    .next_keys([new_n1.qb64])
    .cut_witnesses([old_w1])
    .add_witnesses([new_w4])
    .build()
    .sign_with([new_signer])
```

### 6.10 KeyState View (Read-Only)

Wraps a KeyStateSnapshot with human-readable, domain-concept properties. All properties are read-only.

```
KeyState
  -- Identity --
  .identifier                → from field 'i'
  .sequence_number           → from field 's' (int, not hex)
  .latest_event_said         → from field 'd'
  .prior_event_said          → from field 'p'

  -- Signing Authority --
  .signing_keys              → from field 'k'
  .signing_threshold         → from field 'kt' (Tholder)

  -- Pre-rotation Commitment --
  .next_key_digests          → from field 'n'
  .next_key_threshold        → from field 'nt' (Tholder)

  -- Witness Configuration --
  .witnesses                 → from field 'b'
  .witness_threshold         → from field 'bt' (int)

  -- Timestamps --
  .first_seen_ordinal        → from field 'f'
  .first_seen_datetime       → from field 'dt'

  -- Delegation --
  .delegator                 → from field 'di'

  -- Derived Booleans --
  .is_transferable           → next_key_digests is not empty
  .is_delegated              → delegator is not None and not empty
  .is_establishment_only     → "EO" in config traits
  .is_do_not_delegate        → "DND" in config traits

  -- Last Establishment --
  .last_establishment_sn     → from field 'ee.s'
  .last_establishment_said   → from field 'ee.d'

  -- Builder Integration --
  .prepare_rotation() → RotationBuilder    (pre-filled with i, p=d, s=s+1, wits)
  .prepare_interaction() → InteractionBuilder (pre-filled with i, p=d, s=s+1)
```

Cross-ref: `eventing.py:3599` (`Kever.state` property)

### 6.11 Escrow Query View

```
EscrowReason (enum)
  PARTIAL_SIGNATURES
  PARTIAL_WITNESSES
  OUT_OF_ORDER
  LIKELY_DUPLICITOUS
  PENDING_DELEGATION
  DELEGABLE
  MISFIT_SOURCE
  UNVERIFIED_WITNESS_RECEIPT
  UNVERIFIED_RECEIPT
  UNVERIFIED_TRANSFERABLE_RECEIPT
```

```
PendingEvent
  .event                     → the escrowed event (Serder)
  .reason                    → EscrowReason
  .escrowed_at               → datetime when escrowed
  .signatures_collected      → int (current count)
  .signatures_needed         → int (threshold)
  .witnesses_collected       → int (current witness sig count)
  .witnesses_needed          → int (TOAD)
  .is_expired                → bool (current time > escrowed_at + timeout)
```

**Query interface:**

```
escrows.pending_for(identifier) → list[PendingEvent]
escrows.pending_by_reason(reason) → list[PendingEvent]
escrows.is_pending(identifier, sequence_number) → bool
```

---

## 7. Signature Verification

### 7.1 verifySigs

Cross-ref: `eventing.py:301`

```
verifySigs(raw, signatures, verificationKeys) → (verifiedSigs, indices)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `raw` | bytes | Raw serialized event bytes to verify against |
| `signatures` | list[Siger] | Indexed signatures to verify |
| `verificationKeys` | list[Verfer] | Public verification keys |

**Returns:** Tuple of (list of verified Siger instances, list of verified indices).

**Algorithm:**

1. For each signature in `signatures`:
   a. Extract the signature's index
   b. If index is within bounds of `verificationKeys`, verify the signature against `raw` using the corresponding key
   c. If verification succeeds, include in results
2. Return only verified signatures and their indices

### 7.2 validateSigs

Cross-ref: `eventing.py:349`

```
validateSigs(event, signatures, verificationKeys, threshold) → (verifiedSigs, satisfied)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `event` | Serder | The event to validate |
| `signatures` | list[Siger] | Indexed signatures |
| `verificationKeys` | list[Verfer] | Public verification keys |
| `threshold` | Tholder | Signing threshold to satisfy |

**Returns:** Tuple of (list of verified Siger, bool indicating threshold satisfied).

**Algorithm:**

1. Call `verifySigs(event.raw, signatures, verificationKeys)` to get verified signatures and indices
2. Check whether verified indices satisfy `threshold`:
   - **Simple threshold:** count of verified indices ≥ threshold value
   - **Weighted threshold:** apply weighted satisfaction algorithm (wio) against the fractional weight clauses
3. Return verified signatures and satisfaction boolean

### 7.3 ampleSufficient

```
ampleSufficient(total, faultyCount, weak) → int
```

Computes the BFT-optimal threshold for a given witness or key pool size.

| Parameter | Type | Description |
|-----------|------|-------------|
| `total` | int | Total number of witnesses or keys |
| `faultyCount` | int | Number of tolerated faulty members (default: 0 = auto-compute) |
| `weak` | bool | If true, use weak (simple majority) instead of strong (supermajority) |

**Algorithm (when faultyCount == 0):**

- If `total == 0`: return 0
- Compute maximum tolerable faults: `f = floor((total - 1) / 3)`
- If `weak`: return `max(1, ceil(total / 2) + 1)` — simple majority
- Else (strong): return `max(1, total - f)` — supermajority (optimal BFT: `n - f` where `f = floor((n-1)/3)`)

**Reference values:**

| total | ample (strong) | ample (weak) |
|-------|---------------|-------------|
| 0 | 0 | 0 |
| 1 | 1 | 1 |
| 2 | 2 | 2 |
| 3 | 3 | 2 |
| 4 | 3 | 3 |
| 5 | 4 | 4 |
| 6 | 5 | 4 |

---

## 8. IdentifierState — Aggregate Root

The core domain object. One instance per AID. Encapsulates the full key state of a single identifier and enforces all invariants on state transitions.

Cross-ref: `eventing.py:1584` (`Kever`)

### 8.1 Construction

```
IdentifierState.fromInception(event, signatures, repository, ...) → IdentifierState
```

Creates a new IdentifierState from a validated inception event. This is the ONLY way to create a new identifier.

```
IdentifierState.fromSnapshot(snapshot, repository) → IdentifierState
```

Restores an IdentifierState from a previously persisted KeyStateSnapshot. Used for warm-start from stored state.

Cross-ref: `eventing.py:1654` (`Kever.__init__`), `eventing.py:1961` (`Kever.reload`)

### 8.2 State Properties

| Property | Type | Description | Cross-ref |
|----------|------|-------------|-----------|
| `prefix` | Prefixer | Identifier prefix (AID) | `Kever.prefixer` |
| `sequenceNumber` | int | Current sequence number | `Kever.sner` |
| `firstSeenOrdinal` | int | Monotonic ordinal for first-seen ordering | `Kever.fner` |
| `firstSeenDatetime` | Dater | ISO-8601 timestamp of first acceptance | `Kever.dater` |
| `currentEvent` | Serder | The latest accepted event | `Kever.serder` |
| `eventIlk` | str | Ilk of the current event | `Kever.ilk` |
| `signingKeys` | list[Verfer] | Current signing key verifiers | `Kever.verfers` |
| `signingThreshold` | Tholder | Current signing threshold | `Kever.tholder` |
| `nextKeyDigests` | list[Diger] | Digests of pre-committed next keys | `Kever.ndigers` |
| `nextThreshold` | Tholder | Threshold for next key set | `Kever.ntholder` |
| `witnesses` | list[str] | Current witness AID prefixes | `Kever.wits` |
| `witnessThreshold` | int | TOAD value | `Kever.toader` |
| `witnessCuts` | list[str] | Witnesses removed in last establishment | `Kever.cuts` |
| `witnessAdds` | list[str] | Witnesses added in last establishment | `Kever.adds` |
| `delegatorPrefix` | str | Delegator AID (empty if not delegated) | `Kever.delpre` |
| `isDelegated` | bool | Whether this identifier is delegated | `Kever.delegated` |
| `isEstablishmentOnly` | bool | Whether only establishment events allowed | `Kever.estOnly` |
| `isDoNotDelegate` | bool | Whether delegation is prohibited | `Kever.doNotDelegate` |
| `lastEstablishment` | EstablishmentLocator | (sn, digest) of last establishment event | `Kever.lastEst` |
| `isTransferable` | bool | Whether identifier can rotate (has next key digests) | derived |

### 8.3 Commands

#### applyEvent

```
applyEvent(event, signatures, witnessSignatures,
           delegatorSeqNum, delegatorDigest,
           firstSeenOrdinal, firstSeenDatetime,
           eager, local, readOnly)
```

Validates and applies a non-inception event (rotation, delegated rotation, interaction) to the current state.

Cross-ref: `eventing.py:2089` (`Kever.update`)

**Validation pipeline (called internally):**

1. **`validateRotation(event)`** — field-level rotation checks (thresholds, witnesses, pre-rotation)

   Cross-ref: `eventing.py:2255` (`Kever.rotate`)

2. **`deriveWitnessList(event)`** → (witnesses, cuts, adds) — compute new witness set from current witnesses, cuts, and adds

   Cross-ref: `eventing.py:2357` (`Kever.deriveBacks`)

3. **`validateAuthorization(event, sigs, wigsigs, ...)`** → (sigs, wigs, delpre, delnum, deldiger) — verify controller signatures against threshold, witness signatures against TOAD, delegation seal if applicable

   Cross-ref: `eventing.py:2408` (`Kever.valSigsWigsDel`)

4. **`validateDelegation(event, sigs, wigs, ...)`** → (delegatorSeqNum, delegatorDigest) — for delegated events, verify delegation anchor seal exists in delegator's KEL

   Cross-ref: `eventing.py:2664` (`Kever.validateDelegation`)

5. **`extractPriorNextIndices(signatures)`** → indices — extract exposed prior-next key indices from dual-indexed signatures for rotation pre-rotation threshold check

   Cross-ref: `eventing.py:2617` (`Kever.exposeds`)

#### commitEvent

```
commitEvent(event, signatures, witnessSignatures, witnesses,
            firstSeenOrdinal, firstSeenDatetime,
            delegatorSeqNum, delegatorDigest,
            local, readOnly) → (firstSeenOrdinal, datetime)
```

Persists the validated event and all associated data to the repository. Returns the assigned first-seen ordinal and datetime.

Cross-ref: `eventing.py:3281` (`Kever.logEvent`)

**Persistence actions:**

1. Store serialized event by (prefix, digest)
2. Append digest to KEL index at (prefix, sequence number)
3. Append to first-seen event log, assign ordinal
4. Store controller signatures
5. Store witness signatures
6. Store datetime stamp
7. Store event provenance
8. Store delegation seal (if delegated)
9. Store witness state at establishment events
10. Store updated KeyStateSnapshot

#### snapshot

```
snapshot() → KeyStateSnapshot
```

Exports the current key state as a serializable value object.

Cross-ref: `eventing.py:3599` (`Kever.state` property)

#### keyState

```
keyState() → KeyState
```

Returns a read-only KeyState view wrapping the current state. See [Section 6.10](#610-keystate-view-read-only).

### 8.4 Queries

| Method | Returns | Description |
|--------|---------|-------------|
| `isLocallyOwned(prefix)` | bool | Whether `prefix` is in the processor's local prefix set |
| `isLocallyWitnessed(witnesses)` | bool | Whether any of `witnesses` are in the local prefix set |
| `isLocallyDelegated(delegator)` | bool | Whether `delegator` is in the local prefix set |
| `isLocallyMembered()` | bool | Whether this identifier is a member of a locally-controlled group |

### 8.5 Inception Validation

Cross-ref: `eventing.py:1999` (`Kever.incept`)

When creating an IdentifierState from inception, the following checks MUST be applied:

1. Sequence number MUST be 0
2. Signing keys MUST be non-empty
3. Signing threshold MUST be ≤ number of signing keys
4. SAID MUST match recomputed digest of serialized event body
5. Prefix MUST match derivation from inception event body
6. If non-transferable: next key digests MUST be empty, witnesses MUST be empty, anchored seals MUST be empty
7. No duplicate witness prefixes
8. TOAD within bounds: 0 if no witnesses, 1 ≤ TOAD ≤ |witnesses| otherwise
9. Next key threshold MUST be ≤ number of next key digests (when present)

---

## 9. EventProcessor — Domain Service

Stateless coordinator. Holds references to the repository, domain event bus, and configuration. Does not hold mutable state beyond the identifier cache.

Cross-ref: `eventing.py:3773` (`Kevery`)

### 9.1 Constructor

```
EventProcessor(repository, domainEventBus, config, timeouts)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `repository` | EventRepository | Abstract persistence layer |
| `domainEventBus` | DomainEventBus | FIFO queue for domain events |
| `config` | ProcessorConfig | Behavioral configuration flags |
| `timeouts` | EscrowTimeouts | Timeout values for each escrow type |

### 9.2 Properties

| Property | Type | Description | Cross-ref |
|----------|------|-------------|-----------|
| `identifiers` | map[str → IdentifierState] | Lazy-loading cache of IdentifierState instances, keyed by prefix | `Kevery.kevers` |
| `localPrefixes` | set[str] | Set of locally-controlled AID prefixes | `Kevery.prefixes` |

### 9.3 ingestEvent

```
ingestEvent(event, signatures, witnessSignatures,
            delegatorSeqNum, delegatorDigest,
            firstSeenOrdinal, firstSeenDatetime,
            eager, local)
```

Cross-ref: `eventing.py:3907` (`Kevery.processEvent`)

Main entry point for processing a key event. Dispatches to the appropriate handler based on event ilk and current state.

**Algorithm:**

1. Extract prefix and sequence number from event
2. **If inception event (icp/dip):**
   a. If prefix already in `identifiers`:
      - If existing event SAID matches: accumulate signatures (idempotent)
      - If existing event SAID differs: raise `DuplicitousEventError` → LDE escrow
   b. Else: create new `IdentifierState.fromInception(...)`, add to `identifiers`
3. **If non-inception event (rot/drt/ixn):**
   a. If prefix NOT in `identifiers`: raise `OutOfOrderError` → OOE escrow
   b. If sequence number > current + 1: raise `OutOfOrderError` → OOE escrow
   c. If sequence number ≤ current and NOT a recovery rotation: raise `DuplicitousEventError` → LDE escrow
   d. If sequence number == current + 1 OR is recovery rotation: call `identifierState.applyEvent(...)`
4. **Provenance check** (if `config.defaultLocal` or identifier is locally owned/witnessed/delegated):
   - If event is remote-sourced: raise `ProvenanceMismatchError` → MFE escrow
5. **On success:** call `commitEvent(...)`, produce domain event (EventAccepted or EventNoticed depending on config)
6. **On validation error:** catch specific error type, route to corresponding escrow, store event + signatures + metadata

### 9.4 ingestReceipt

```
ingestReceipt(receipt, nonTransferableSignatures, witnessSignatures,
              transferableSignatureGroups, local)
```

Cross-ref: `eventing.py:4124` (`Kevery.processReceipt`)

Processes a receipt message for an existing event.

**Algorithm:**

1. Extract prefix, sequence number, and SAID from receipt
2. Look up the receipted event in the repository
3. **If receipted event NOT found:**
   - Non-transferable receipts → raise `UnverifiedReceiptError` → URE escrow
   - Witness receipts → raise `UnverifiedWitnessReceiptError` → UWE escrow
   - Transferable receipts → raise `UnverifiedTransferableReceiptError` → VRE escrow
4. **If receipted event found:**
   - Verify each signature against the receipter's known keys
   - Store verified receipts in appropriate repository tables
   - Accumulate: if receipts already exist, union with new receipts

### 9.5 resolveEscrows

```
resolveEscrows()
```

Cross-ref: `eventing.py:5586` (`Kevery.processEscrows`)

Periodic sweep of all escrow types. Attempts to re-validate escrowed events and receipts. Events that now pass validation are accepted; events that have timed out are removed.

**Processing order** (earlier resolution MAY unblock later):

```
OOE → UWE → URE → VRE → PDE → PWE → PSE → LDE
```

This order is significant: resolving an out-of-order event may provide the receipted event needed to resolve a UWE entry, which may provide witness signatures needed to resolve a PWE entry.

See [Section 11](#11-escrow-system) for detailed escrow processing.

---

## 10. EventRepository — Repository Interface

Abstract persistence boundary. Implementations MUST provide all methods defined here. The interface is organized into 6 categories covering ~40 methods.

Cross-ref: `basing.py:164` (`Baser`)

### 10.1 Key Construction

Two helper functions construct database keys:

```
digestKey(prefix, digest) → key
```
Identifies a specific event version. Used for event storage, signature storage, datetime storage.

```
sequenceKey(prefix, sequenceNumber) → key
```
Identifies events at a given sequence number. Used for KEL log indexes, escrow indexes.

### 10.2 Event Storage

| Method | Description | Cross-ref |
|--------|-------------|-----------|
| `storeEvent(prefix, digest, event)` | Store serialized event bytes by (prefix, digest) | `basing.py:589` (`.evts`) |
| `retrieveEvent(prefix, digest) → Event or None` | Retrieve event by (prefix, digest) | `.evts` |

### 10.3 Log Indexes

| Method | Description | Cross-ref |
|--------|-------------|-----------|
| `appendToEventLog(prefix, sequenceNumber, digest)` | Append digest to KEL at (prefix, sn) | `basing.py:591` (`.kels`) |
| `getLastEventDigest(prefix, sequenceNumber) → str or None` | Get last digest at (prefix, sn) | `.kels` |
| `iterateEventLogBackward(prefix) → iterator` | Iterate KEL entries in reverse sn order | `.kels` |
| `appendToFirstSeenLog(prefix, ordinal, digest)` | Append to first-seen event log | `basing.py:590` (`.fels`) |
| `storeFirstSeenOrdinal(prefix, digest, ordinal)` | Store first-seen ordinal number | `basing.py:618` (`.fons`) |
| `getFirstSeenOrdinal(prefix, digest) → int or None` | Retrieve first-seen ordinal | `.fons` |

### 10.4 Signature Storage

| Method | Description | Cross-ref |
|--------|-------------|-----------|
| `storeControllerSignatures(prefix, digest, signatures)` | Store indexed controller Sigers | `basing.py:595` (`.sigs`) |
| `retrieveControllerSignatures(prefix, digest) → list[Siger]` | Retrieve stored Sigers | `.sigs` |
| `storeWitnessSignatures(prefix, digest, signatures)` | Store indexed witness Sigers | `basing.py:597` (`.wigs`) |
| `retrieveWitnessSignatures(prefix, digest) → list[Siger]` | Retrieve stored witness Sigers | `.wigs` |
| `storeNonTransferableReceipts(prefix, digest, couples)` | Store (Prefixer, Cigar) couples | `basing.py:598` (`.rcts`) |
| `retrieveNonTransferableReceipts(prefix, digest) → list[(Prefixer, Cigar)]` | Retrieve receipt couples | `.rcts` |
| `storeTransferableReceipts(prefix, digest, quadruples)` | Store (Prefixer, Number, Diger, Siger) quadruples | `basing.py:602` (`.vrcs`) |
| `retrieveTransferableReceipts(prefix, digest) → list[(Prefixer, Number, Diger, Siger)]` | Retrieve receipt quadruples | `.vrcs` |

### 10.5 Metadata

| Method | Description | Cross-ref |
|--------|-------------|-----------|
| `storeDatetime(prefix, digest, dater)` | Store first-seen datetime | `basing.py:592` (`.dtss`) |
| `retrieveDatetime(prefix, digest) → Dater or None` | Retrieve datetime | `.dtss` |
| `storeProvenance(prefix, digest, provenance)` | Store EventProvenance | `basing.py:624` (`.esrs`) |
| `retrieveProvenance(prefix, digest) → EventProvenance or None` | Retrieve provenance | `.esrs` |
| `storeDelegationSeal(prefix, digest, seqNum, diger)` | Store delegation (Number, Diger) | `basing.py:593` (`.aess`) |
| `retrieveDelegationSeal(prefix, digest) → (Number, Diger) or None` | Retrieve delegation seal | `.aess` |
| `removeDelegationSeal(prefix, digest)` | Remove delegation seal entry | `.aess` |
| `storeWitnessState(prefix, digest, witnesses)` | Store witness list at establishment | `basing.py:640` (`.wits`) |
| `retrieveWitnessState(prefix, digest) → list[Prefixer] or None` | Retrieve witness state | `.wits` |
| `storeKeyStateSnapshot(prefix, snapshot)` | Store KeyStateSnapshot | `basing.py:636` (`.states`) |
| `retrieveKeyStateSnapshot(prefix) → KeyStateSnapshot or None` | Retrieve latest snapshot | `.states` |

### 10.6 Escrow Storage

For each of the 10 escrow types, the repository MUST provide three operations:

```
addToEscrow_{TYPE}(prefix, sequenceNumber, digest)
iterateEscrow_{TYPE}() → iterator[(prefix, sequenceNumber, digest)]
removeFromEscrow_{TYPE}(prefix, sequenceNumber, digest)
```

| Escrow Type | Abbreviation | Index Sub-DB | Cross-ref |
|-------------|-------------|-------------|-----------|
| Out of Order | OOE | `.ooes` | `basing.py:611` |
| Partial Signatures | PSE | `.pses` | `basing.py:606` |
| Partial Witnesses | PWE | `.pwes` | `basing.py:607` |
| Partial Delegation | PDE | `.pdes` | `basing.py:608` |
| Delegable | delegable | `.delegables` | `basing.py:632` |
| Misfit Source | MFE | `.misfits` | `basing.py:629` |
| Unverified Witness Receipt | UWE | `.uwes` | `basing.py:610` |
| Unverified Non-Trans Receipt | URE | `.ures` | `basing.py:600` |
| Unverified Trans Receipt | VRE | `.vres` | `basing.py:604` |
| Likely Duplicitous | LDE | `.ldes` | `basing.py:614` |

Shared storage: escrowed events and their signatures are stored using the same event and signature storage methods (Sections 10.2, 10.4). The escrow-specific tables are **index-only** — they track which (prefix, sn, digest) tuples are in each escrow.

### 10.7 Queries

| Method | Description |
|--------|-------------|
| `findSealingEvent(prefix, sealDigest) → Event or None` | Walk the KEL of `prefix` to find an event whose anchor data contains a seal matching `sealDigest`. Used for delegation validation. |

---

## 11. Escrow System

The escrow system follows a three-phase pattern for all escrow types:

### 11.1 Three-Phase Pattern

**Phase 1 — Entry:**
A validation error is raised during `ingestEvent` or `ingestReceipt`. The specific error type determines the target escrow. The event, its signatures, and metadata (datetime, provenance) are stored in shared tables, and the escrow index is updated.

**Phase 2 — Storage:**
Escrowed entries use shared storage tables (events, signatures, witness signatures, datetimes, provenance) with per-escrow index tables tracking membership. This means the same event bytes and signature data are stored once, even if referenced by multiple escrow indexes (though in practice an event is typically in only one escrow at a time).

**Phase 3 — Resolution:**
`resolveEscrows()` periodically sweeps all escrow types in defined order. For each escrowed entry:
1. Check timeout — if expired, remove from escrow and optionally produce a `EventQueryNeeded` domain event
2. Re-validate — attempt the same validation that originally failed
3. If validation now succeeds: remove from escrow, accept event via normal path
4. If validation still fails with the same error: leave in escrow
5. If validation fails with a **different** error: remove from current escrow, route to new escrow

### 11.2 Processing Order

```
OOE → UWE → URE → VRE → PDE → PWE → PSE → LDE
```

This order is normative. Earlier escrow resolution can unblock later escrow entries:

- Resolving an OOE (out-of-order) event provides a new event in the KEL, which may be the event needed by a UWE (unverified witness receipt) entry
- Resolving a UWE provides additional witness signatures, which may satisfy the TOAD needed by a PWE (partial witnesses) entry
- And so forth through the cascade

**Cascade example:**

```
1. Event at sn=2 arrives → prior sn=1 missing → OOE
2. Witness receipt for sn=2 arrives → event sn=2 not accepted → UWE
3. Event at sn=1 arrives → accepted
4. resolveEscrows():
   a. OOE sweep: sn=2 now has prior → re-validate → accepted (but maybe PSE/PWE)
   b. UWE sweep: sn=2 now accepted → receipt stored → may provide needed wigs
   c. PWE sweep: sn=2 now has enough wigs → fully accepted
```

### 11.3 Escrow Type Details

#### Out of Order Events (OOE)

Cross-ref: `eventing.py:5609` (`Kevery.processEscrowOutOfOrders`)

- **Entry:** Prior event at sn-1 not in KEL
- **Resolution:** Re-process with `ingestEvent`; if prior now exists, event accepted
- **Timeout:** 1200 seconds (reference default)
- **On timeout:** Remove from escrow, produce `EventQueryNeeded(prefix, sn-1)` domain event

#### Partial Signatures Events (PSE)

Cross-ref: `eventing.py:5737` (`Kevery.processEscrowPartialSigs`)

- **Entry:** Controller signatures below signing threshold
- **Resolution:** Accumulate signatures from duplicate arrivals; re-check threshold
- **Timeout:** 3600 seconds
- **Signature accumulation:** When same event arrives with different signatures, union with stored signatures before threshold check

#### Partial Witnesses Events (PWE)

Cross-ref: `eventing.py:5892` (`Kevery.processEscrowPartialWigs`)

- **Entry:** Witness signatures below TOAD
- **Resolution:** Accumulate witness signatures; re-check TOAD
- **Timeout:** 3600 seconds

#### Partial Delegation Events (PDE)

Cross-ref: `eventing.py:6043` (`Kevery.processEscrowPartialDels`)

- **Entry:** Delegation seal not found in delegator's KEL
- **Resolution:** Re-check delegator's KEL for anchor seal via `findSealingEvent`
- **Timeout:** 3600 seconds

#### Delegable Events (delegable)

Cross-ref: `eventing.py:6460` (`Kevery.processEscrowDelegables`)

- **Entry:** Local delegator has not yet anchored approval interaction
- **Resolution:** Check if delegator has anchored the required seal
- **Timeout:** 3600 seconds
- **Note:** This escrow is specific to the delegator's perspective — the delegator's own system holds events pending local approval

#### Misfit Source Events (MFE)

Cross-ref: `basing.py:629` (`.misfits`)

- **Entry:** Remote-sourced event for a locally-controlled, locally-witnessed, or locally-delegated identifier
- **Resolution:** Same event arrives from local source → accepted
- **Timeout:** 3600 seconds
- **Security purpose:** Prevents a remote party from updating state for an identifier the local controller owns

#### Unverified Witness Receipts (UWE)

Cross-ref: `eventing.py:6200` (`Kevery.processEscrowUnverWitness`)

- **Entry:** Witness receipt arrived before the receipted event
- **Resolution:** Receipted event now in KEL → verify and store receipt
- **Timeout:** 3600 seconds

#### Unverified Non-Transferable Receipts (URE)

Cross-ref: `eventing.py:6306` (`Kevery.processEscrowUnverNonTrans`)

- **Entry:** Non-transferable (Cigar-based) receipt arrived before the receipted event
- **Resolution:** Receipted event now in KEL → verify and store receipt
- **Timeout:** 3600 seconds

#### Unverified Transferable Receipts (VRE)

Cross-ref: `eventing.py:6775` (`Kevery.processEscrowUnverTrans`)

- **Entry:** Transferable (Siger-based with validator prefix+sn+dig) receipt arrived before the receipted event
- **Resolution:** Receipted event now in KEL → verify and store receipt
- **Timeout:** 3600 seconds

#### Likely Duplicitous Events (LDE)

Cross-ref: `eventing.py:6935` (`Kevery.processEscrowDuplicitous`)

- **Entry:** Different event (different SAID) at same (prefix, sequence number) as an already-accepted event
- **Resolution:** LDE entries persist as evidence of duplicity; they are NOT re-processed for acceptance
- **Timeout:** 3600 seconds (for evidence retention; entries are tracked, not re-validated)
- **Note:** LDE is a record of detected duplicity, useful for forensic analysis

### 11.4 Escrow Timeouts (Reference Defaults)

Cross-ref: `eventing.py:3812` (timeout constants)

| Escrow | Timeout (seconds) | Constant |
|--------|-------------------|----------|
| OOE | 1200 | `TimeoutOOE` |
| PSE | 3600 | `TimeoutPSE` |
| PWE | 3600 | `TimeoutPWE` |
| PDE | 3600 | (uses PSE timeout) |
| delegable | 3600 | (uses PSE timeout) |
| MFE | 3600 | (uses PSE timeout) |
| UWE | 3600 | `TimeoutUWE` |
| URE | 3600 | `TimeoutURE` |
| VRE | 3600 | `TimeoutVRE` |
| LDE | 3600 | `TimeoutLDE` |

These are reference defaults, not normative. Implementations SHOULD make timeouts configurable.

---

## 12. Domain Events

Typed signals the library produces for infrastructure consumption. The library pushes domain events onto a `DomainEventBus` (FIFO queue); the infrastructure layer drains and acts on them.

Domain events replace direct coupling to networking or framework code. The library never sends a network message or starts a server — it produces domain events that tell the infrastructure layer what is needed.

### 12.1 Domain Event Types

| Domain Event | Trigger | Purpose |
|--------------|---------|---------|
| `EventAccepted(event)` | Successful acceptance in direct mode | Infrastructure should send a receipt to witnesses/validators |
| `EventNoticed(event)` | Successful acceptance in indirect mode | Infrastructure should notify watchers |
| `WitnessReceiptNeeded(event)` | Locally-witnessed event accepted | Infrastructure should generate a witness receipt |
| `EventQueryNeeded(prefix, sequenceNumber)` | Escrow timeout for missing event | Infrastructure should query peers for the missing event |
| `CloneMismatchDetected(event, expectedOrdinal, actualOrdinal)` | Replay mode: first-seen ordinal mismatch | Infrastructure should flag replay inconsistency |
| `RemoteGroupSignatureReceived(event, index)` | Remote signature for locally-controlled group member | Infrastructure should forward to group coordination |

### 12.2 DomainEventBus

```
DomainEventBus
  .push(domainEvent)        — add domain event to FIFO queue
  .pull() → domainEvent     — remove and return next domain event (or None if empty)
  .drain() → list           — remove and return all pending domain events
  .isEmpty() → bool         — check if queue is empty
```

**Ordering guarantee:** Domain events MUST be delivered in the order they were pushed. The bus is a strict FIFO queue.

**Ownership:** The EventProcessor pushes domain events. The infrastructure layer (outside scope of this spec) drains them. The bus is passed into the EventProcessor constructor.

---

## 13. Invariant Contract

The following 14 invariants MUST be enforced by the library. Violations MUST result in rejection of the offending event (via the appropriate error type from [Section 5](#5-error-hierarchy)).

1. **Inception sequence number:** The sequence number (`s` field) of an inception event MUST be 0.

2. **Monotonic sequence numbers:** For each accepted non-inception event, the sequence number MUST equal the previous event's sequence number plus 1 (except for recovery rotations, which MAY supersede at the same sequence number).

3. **Prior event digest chaining:** For every non-inception event, the prior event digest (`p` field) MUST equal the SAID of the immediately preceding accepted event in the KEL.

4. **Single first-seen event:** For each (prefix, sequence number) pair, at most one event SAID MAY be accepted into the first-seen event log. A different SAID at the same (prefix, sn) is duplicitous.

5. **Signing threshold satisfaction:** Controller signatures on every event MUST satisfy the current signing threshold (`kt` field) as evaluated by the Tholder.

6. **Pre-rotation commitment:** On rotation events, the new signing keys MUST satisfy the prior event's next-key digest commitment. Specifically, the digests of the new keys MUST match the `n` field digests from the previous establishment event, and the prior next threshold (`nt`) MUST be satisfied by the indices of dual-indexed signatures.

7. **Witness threshold (TOAD) satisfaction:** Witness signatures on every event MUST meet or exceed the TOAD value (`bt` field) when witnesses are configured.

8. **Non-transferable rotation prohibition:** A non-transferable identifier (one whose inception has empty next key digests) MUST NOT have rotation events.

9. **Non-transferable constraints:** A non-transferable inception MUST have empty witnesses (`b`), empty next key digests (`n`), and empty anchor seals (`a`).

10. **Delegation seal presence:** For delegated events (`dip`, `drt`), a valid delegation anchor seal MUST exist in the delegator's KEL.

11. **No duplicate witnesses:** No establishment event MAY contain duplicate witness prefixes in the resulting witness list.

12. **Witness cut/add set integrity:** Witness cuts (`br`) MUST be a subset of current witnesses. Witness adds (`ba`) MUST NOT overlap with current witnesses. Cuts and adds MUST NOT overlap with each other.

13. **TOAD bounds:** If no witnesses are configured, TOAD MUST be 0. If witnesses are configured, TOAD MUST satisfy 1 ≤ TOAD ≤ |witnesses|.

14. **Local provenance requirement:** Events for locally-controlled identifiers MUST originate from a local source. Remote-sourced events for locally-owned, locally-witnessed, or locally-delegated identifiers are rejected as provenance mismatches.

---

## 14. Configuration

### 14.1 ProcessorConfig

Cross-ref: `eventing.py:3822` (`Kevery.__init__` parameters)

```
ProcessorConfig
    promiscuous: bool = true     # accept events for any AID
    defaultLocal: bool = false   # default provenance assumption
    replayMode: bool = false     # use attached timestamps
    directMode: bool = true      # produce receipt domain events
    readOnly: bool = false       # skip non-idempotent writes
```

| Flag | Default | keripy Equivalent | Description |
|------|---------|-------------------|-------------|
| `promiscuous` | `true` | `lax=True` | When true, accept events for any AID prefix. When false, only accept events for AIDs in `localPrefixes`. |
| `defaultLocal` | `false` | `local=False` | When true, treat events as local-sourced by default (enables provenance mismatch protection for all AIDs). |
| `replayMode` | `false` | `cloned=False` | When true, use attached first-seen ordinals and datetimes from event attachments instead of assigning fresh values. Used for replaying/cloning a KEL from another source. |
| `directMode` | `true` | `direct=True` | When true, produce `EventAccepted` domain events (for sending receipts). When false, produce `EventNoticed` domain events instead. |
| `readOnly` | `false` | `check=False` | When true, skip non-idempotent writes (no first-seen log appends, no timestamp assignment). Used for re-initialization validation against an existing KEL. |

### 14.2 EscrowTimeouts

```
EscrowTimeouts
    outOfOrder: int = 1200
    partialSignatures: int = 3600
    partialWitnesses: int = 3600
    partialDelegation: int = 3600
    delegable: int = 3600
    misfitSource: int = 3600
    unverifiedWitnessReceipt: int = 3600
    unverifiedReceipt: int = 3600
    unverifiedTransferableReceipt: int = 3600
    likelyDuplicitous: int = 3600
```

All values are in seconds. Implementations SHOULD allow these to be overridden at construction time.

---

## 15. Test Specification

A comprehensive test suite exercising every aspect of the library. Tests are organized by category and use DDD domain names. Each test has a clear name, description, and expected behavior. Implementations MUST pass all tests to be considered conformant.

### 15.1 Event Builder Tests

| # | Test Name | Description |
|---|-----------|-------------|
| B01 | `inceptionBuilder_minimalValid` | InceptionBuilder with one key, no witnesses. Verify ilk=icp, sn=0, SAID computed, field `k` populated. |
| B02 | `inceptionBuilder_fullConfig` | InceptionBuilder with multiple keys, weighted threshold, next keys (auto-digested), witnesses, TOAD, config traits (EO, DND), and seals. Verify all wire fields populated. |
| B03 | `inceptionBuilder_nonTransferable` | InceptionBuilder.non_transferable() — verify .next_keys()/.witnesses()/.anchored_seals() unavailable (type narrowing). Verify prefix is non-transferable code. |
| B04 | `inceptionBuilder_selfAddressing` | Self-addressing derivation. Verify prefix (`i` field) is SAID of inception event. |
| B05 | `inceptionBuilder_defaultThresholds` | Omit signing_threshold and next_key_threshold. Verify defaults: ceil(len(k)/2) and ceil(len(n)/2). |
| B06 | `inceptionBuilder_defaultWitnessThreshold` | Omit witness_threshold. Verify default: ample(len(b)). |
| B07 | `inceptionBuilder_autoDigestsNextKeys` | Provide raw keys via .next_keys(). Verify field `n` contains Blake3-256 digests, NOT the raw keys. |
| B08 | `inceptionBuilder_rejectEmptyKeys` | InceptionBuilder with no .signing_keys(). Expect build-time validation error. |
| B09 | `inceptionBuilder_rejectThresholdExceedsKeys` | .signing_threshold(5) with 3 keys. Expect build-time validation error. |
| B10 | `inceptionBuilder_rejectDuplicateWitnesses` | .witnesses([w1, w1]). Expect build-time validation error. |
| B11 | `rotationBuilder_basic` | RotationBuilder with new keys, prior digest, sn=1. Verify ilk=rot, field `p` matches. |
| B12 | `rotationBuilder_fromKeyState` | RotationBuilder.from_key_state(state) pre-fills identifier, previous_event, sequence_number. Verify fields `i`, `p`, `s`. |
| B13 | `rotationBuilder_withWitnessChange` | .cut_witnesses() + .add_witnesses(). Verify fields `br`/`ba` populated. |
| B14 | `rotationBuilder_withSeals` | .anchored_seals(). Verify field `a` populated. |
| B15 | `interactionBuilder_basic` | InteractionBuilder. Verify ilk=ixn, no key fields. |
| B16 | `interactionBuilder_fromKeyState` | InteractionBuilder.from_key_state(state) pre-fills identifier, previous_event, sn+1. |
| B17 | `interactionBuilder_emptySeals` | Empty .anchored_seals([]). Valid — used for anchoring. |
| B18 | `delegatedInceptionBuilder_basic` | DelegatedInceptionBuilder with .delegator(). Verify ilk=dip, field `di` set. |
| B19 | `delegatedRotationBuilder_basic` | DelegatedRotationBuilder. Verify ilk=drt. |
| B20 | `receiptBuilder_basic` | ReceiptBuilder.for_event(). Verify ilk=rct, fields `i`, `s`, `d`. |
| B21 | `builder_SAID_selfVerifying` | Verify SAID in field `d` matches recomputed digest of serialized event body. |
| B22 | `builder_multipleSerializationFormats` | Same logical event in JSON, CBOR, MsgPack. SAID differs across formats. |

### 15.2 Seal Builder Tests

| # | Test Name | Description |
|---|-----------|-------------|
| SB01 | `eventSeal_of` | EventSeal.of(identifier, sn, digest). Verify {i, s, d} field map. |
| SB02 | `digestSeal_of` | DigestSeal.of(digest). Verify {d} field map. |
| SB03 | `rootSeal_of` | RootSeal.of(digest). Verify {rd} field map. |
| SB04 | `sourceSeal_of` | SourceSeal.of(sn, digest). Verify {s, d} field map. |
| SB05 | `lastEstSeal_of` | LastEstSeal.of(identifier). Verify {i} field map. |
| SB06 | `backerSeal_of` | BackerSeal.of(backer_prefix, digest). Verify {bi, d} field map. |
| SB07 | `kindSeal_of` | KindSeal.of(type_version, digest). Verify {t, d} field map. |
| SB08 | `seal_composability` | Multiple seal types in single .anchored_seals([]) call. Verify all preserved in field `a`. |

### 15.3 SignedEvent and KeyState View Tests

| # | Test Name | Description |
|---|-----------|-------------|
| SV01 | `signedEvent_signWith` | event.sign_with([signer]) → SignedEvent with correct Siger indices. |
| SV02 | `signedEvent_multipleSigners` | event.sign_with([s1, s2, s3]) → SignedEvent with 3 indexed Sigers. |
| SV03 | `keyState_fromSnapshot` | KeyState from KeyStateSnapshot. Verify all domain properties map to wire fields. |
| SV04 | `keyState_signingAuthority` | Verify .signing_keys maps to field `k`, .signing_threshold maps to field `kt`. |
| SV05 | `keyState_preRotationCommitment` | Verify .next_key_digests maps to field `n`, .next_key_threshold maps to field `nt`. |
| SV06 | `keyState_witnessConfiguration` | Verify .witnesses maps to field `b`, .witness_threshold maps to field `bt`. |
| SV07 | `keyState_derivedBooleans` | .is_transferable, .is_delegated, .is_establishment_only, .is_do_not_delegate. |
| SV08 | `keyState_prepareRotation` | .prepare_rotation() → RotationBuilder pre-filled with identifier, previous_event, sn+1. |
| SV09 | `keyState_prepareInteraction` | .prepare_interaction() → InteractionBuilder pre-filled with identifier, previous_event, sn+1. |
| SV10 | `keyState_fluentChain` | key_state.prepare_rotation().signing_keys(...).build().sign_with(...) — full fluent chain. |
| SV11 | `pendingEvent_view` | PendingEvent from escrowed data. Verify .reason, .signatures_collected, .is_expired. |
| SV12 | `escrowQuery_pendingFor` | escrows.pending_for(identifier) returns correct PendingEvent list. |
| SV13 | `escrowQuery_pendingByReason` | escrows.pending_by_reason(PARTIAL_SIGNATURES) filters correctly. |

### 15.4 IdentifierState — Inception Validation Tests

| # | Test Name | Description |
|---|-----------|-------------|
| I01 | `inception_validMinimal` | Create IdentifierState from valid minimal inception. Verify state: sn=0, keys, threshold, prefix. |
| I02 | `inception_validFull` | Create from inception with all fields (witnesses, TOAD, next keys, config, seals). Verify complete state. |
| I03 | `inception_rejectNonZeroSn` | Inception with sn != 0. Expect ValidationError. |
| I04 | `inception_rejectEmptyKeys` | Inception with empty key list. Expect ValidationError. |
| I05 | `inception_rejectThresholdExceedsKeys` | Signing threshold > number of keys. Expect ValidationError. |
| I06 | `inception_rejectDuplicateWitnesses` | Inception with duplicate witness prefixes. Expect ValidationError. |
| I07 | `inception_rejectTOADExceedsWitnesses` | TOAD > number of witnesses. Expect ValidationError. |
| I08 | `inception_rejectTOADZeroWithWitnesses` | TOAD=0 but witnesses present. Expect ValidationError. |
| I09 | `inception_rejectNonTransWithWitnesses` | Non-transferable prefix with witnesses. Expect ValidationError. |
| I10 | `inception_rejectNonTransWithNextDigests` | Non-transferable prefix with non-empty next digests. Expect ValidationError. |
| I11 | `inception_rejectNonTransWithSeals` | Non-transferable prefix with anchor seals. Expect ValidationError. |
| I12 | `inception_SAIDVerification` | Inception with tampered SAID. Expect ValidationError (SAID mismatch). |
| I13 | `inception_prefixDerivation` | Verify computed prefix matches derivation from inception event body. |
| I14 | `inception_establishmentOnlyTrait` | Inception with EO trait. Verify estOnly=true on state. |
| I15 | `inception_doNotDelegateTrait` | Inception with DND trait. Verify doNotDelegate=true on state. |
| I16 | `inception_weightedThreshold` | Inception with fractional weighted threshold. Verify Tholder state. |
| I17 | `inception_multipleKeys` | Inception with 3 keys and threshold 2. Verify all keys in state. |

### 15.5 IdentifierState — Rotation Validation Tests

| # | Test Name | Description |
|---|-----------|-------------|
| R01 | `rotation_validBasic` | Rotate with new keys, correct prior digest, sn=1. Verify state updated. |
| R02 | `rotation_rejectWrongPriorDigest` | Rotation with incorrect prior digest. Expect ValidationError. |
| R03 | `rotation_rejectNonSequentialSn` | Rotation sn != current_sn + 1 (and not recovery). Expect OutOfOrderError. |
| R04 | `rotation_rejectNonTransferable` | Rotate a non-transferable identifier. Expect ValidationError. |
| R05 | `rotation_rejectThresholdExceedsKeys` | New threshold > new key count. Expect ValidationError. |
| R06 | `rotation_witnessAdd` | Add a new witness. Verify wits list updated. |
| R07 | `rotation_witnessCut` | Remove a witness. Verify wits list updated. |
| R08 | `rotation_witnessCutAndAdd` | Simultaneous cut and add. Verify correct final witness list. |
| R09 | `rotation_rejectDuplicateCuts` | Duplicate entries in cuts list. Expect ValidationError. |
| R10 | `rotation_rejectDuplicateAdds` | Duplicate entries in adds list. Expect ValidationError. |
| R11 | `rotation_rejectCutNotInWitnessList` | Cut a witness not currently in list. Expect ValidationError. |
| R12 | `rotation_rejectAddAlreadyInWitnessList` | Add a witness already present. Expect ValidationError. |
| R13 | `rotation_rejectCutAndAddOverlap` | Same prefix in both cuts and adds. Expect ValidationError. |
| R14 | `rotation_TOADUpdateValid` | Update TOAD during witness rotation. Verify new TOAD. |
| R15 | `rotation_rejectTOADExceedsNewWitnesses` | New TOAD > new witness count. Expect ValidationError. |
| R16 | `rotation_preRotationCommitment` | Verify new keys satisfy prior next-key digest commitment. |
| R17 | `rotation_rejectPreRotationMismatch` | New keys don't match prior next digests. Expect InsufficientSignaturesError. |
| R18 | `rotation_partialKeyUpdate` | Rotate only some keys (partial rotation). Verify mixed key state. |
| R19 | `rotation_noKeyChange` | Rotation with same keys (witness-only rotation). Verify keys unchanged. |
| R20 | `rotation_emptyNextDigests` | Rotation to non-transferable (abandon). Verify ndigers empty. |
| R21 | `rotation_weightedThresholdChange` | Change from simple to weighted threshold on rotation. |

### 15.6 IdentifierState — Interaction Validation Tests

| # | Test Name | Description |
|---|-----------|-------------|
| X01 | `interaction_validBasic` | Valid interaction with seal data. Verify sn incremented, keys unchanged. |
| X02 | `interaction_rejectWrongPriorDigest` | Interaction with wrong prior digest. Expect ValidationError. |
| X03 | `interaction_rejectNonSequentialSn` | Interaction sn != current_sn + 1. Expect ValidationError. |
| X04 | `interaction_rejectEstablishmentOnly` | Interaction on identifier with EO trait. Expect ValidationError. |
| X05 | `interaction_emptySeals` | Interaction with empty data array. Valid. |
| X06 | `interaction_multipleSeals` | Interaction with multiple anchor seals. Verify all preserved. |
| X07 | `interaction_stateUnchanged` | Verify signing keys, witnesses, thresholds unchanged after interaction. |

### 15.7 IdentifierState — Delegation Validation Tests

| # | Test Name | Description |
|---|-----------|-------------|
| D01 | `delegatedInception_valid` | Create delegated identifier with delegator anchor seal. Verify delpre and delegated=true. |
| D02 | `delegatedInception_rejectMissingDelegatorSeal` | Delegated inception without anchor seal. Expect MissingDelegationError. |
| D03 | `delegatedRotation_valid` | Rotate delegated identifier with correct delegator seal. |
| D04 | `delegatedRotation_rejectMissingApproval` | Delegated rotation without delegator approval. Expect PendingDelegationApprovalError. |
| D05 | `delegation_supersedingRotation` | Recovery rotation with later delegator seal supersedes prior. |
| D06 | `delegation_supersedingRuleB1` | Superseding: new delegating sn > old delegating sn. |
| D07 | `delegation_supersedingRuleB2` | Superseding: same delegating sn, later seal index. |
| D08 | `delegation_doNotDelegateReject` | Attempt delegation from DND identifier. Expect ValidationError. |

### 15.8 Signature Verification Tests

| # | Test Name | Description |
|---|-----------|-------------|
| S01 | `verifySigs_allValid` | All signatures verify against keys. Return all indices. |
| S02 | `verifySigs_someInvalid` | Mix of valid and invalid sigs. Return only valid indices. |
| S03 | `verifySigs_noneValid` | No signatures verify. Return empty. |
| S04 | `verifySigs_duplicateIndices` | Duplicate signature indices. Return unique only. |
| S05 | `validateSigs_simpleThresholdMet` | Simple threshold (e.g., 2 of 3) satisfied. |
| S06 | `validateSigs_simpleThresholdNotMet` | Threshold not met. Return satisfied=false. |
| S07 | `validateSigs_weightedThresholdMet` | Fractional weighted threshold satisfied (wio algorithm). |
| S08 | `validateSigs_weightedThresholdNotMet` | Weighted threshold not satisfied. |
| S09 | `validateSigs_weightedMultiClause` | Multi-clause weighted threshold (AND of OR clauses). |
| S10 | `validateSigs_weightedWithKeyedWeights` | Nested keyed weights in weighted threshold. |
| S11 | `ampleSufficient_basic` | BFT threshold: ample(3) = 3, ample(4) = 3, ample(6) = 5. |
| S12 | `ampleSufficient_withFaults` | ample(n, f) for specific fault counts. |
| S13 | `ampleSufficient_weakVsStrong` | Weak vs non-weak ample majority difference. |

### 15.9 Authorization Validation Tests

| # | Test Name | Description |
|---|-----------|-------------|
| A01 | `auth_controllerSigsSatisfied` | Controller signatures meet threshold → accept. |
| A02 | `auth_controllerSigsInsufficient` | Controller sigs below threshold → InsufficientSignaturesError → PSE escrow. |
| A03 | `auth_witnessSigsSatisfied` | Witness sigs meet TOAD → accept. |
| A04 | `auth_witnessSigsInsufficient` | Witness sigs below TOAD → InsufficientWitnessesError → PWE escrow. |
| A05 | `auth_priorNextThresholdMet` | Rotation: prior next threshold satisfied via exposeds. |
| A06 | `auth_priorNextThresholdNotMet` | Rotation: prior next threshold NOT satisfied → InsufficientSignaturesError. |
| A07 | `auth_delegationSealPresent` | Delegated event with valid delegator seal → accept. |
| A08 | `auth_delegationSealMissing` | Delegated event without seal → MissingDelegationError → PDE escrow. |
| A09 | `auth_provenanceMismatch` | Remote-sourced event for locally-owned AID → ProvenanceMismatchError → MFE escrow. |
| A10 | `auth_provenanceMismatch_witnessed` | Remote event for locally-witnessed AID → MFE escrow. |
| A11 | `auth_provenanceMismatch_delegated` | Remote event for locally-delegated AID → MFE escrow. |
| A12 | `auth_localSourceAccepted` | Local-sourced event for locally-owned AID → accepted. |

### 15.10 EventProcessor — Event Ingestion Tests

| # | Test Name | Description |
|---|-----------|-------------|
| P01 | `ingest_inceptionCreatesIdentifier` | Ingest valid inception → IdentifierState created in identifiers map. |
| P02 | `ingest_inceptionProducesDomainEvent` | Ingest inception → EventAccepted domain event produced. |
| P03 | `ingest_rotationUpdatesState` | Ingest rotation → IdentifierState.applyEvent called, state updated. |
| P04 | `ingest_interactionUpdatesState` | Ingest interaction → state updated, keys unchanged. |
| P05 | `ingest_duplicateInceptionSameSAID` | Second inception with same SAID → idempotent (accumulate sigs). |
| P06 | `ingest_duplicateInceptionDifferentSAID` | Different inception at sn=0 → DuplicitousEventError → LDE escrow. |
| P07 | `ingest_duplicateRotationDifferentSAID` | Different event at same sn → DuplicitousEventError → LDE escrow. |
| P08 | `ingest_outOfOrder` | Event with sn > current+1 → OutOfOrderError → OOE escrow. |
| P09 | `ingest_nonInceptionForUnknownPrefix` | Non-inception event for unknown prefix → OOE escrow. |
| P10 | `ingest_staleEvent` | Event at sn ≤ current and not recovery → DuplicitousEventError. |
| P11 | `ingest_recoveryRotation` | Recovery rotation superseding prior interaction → accepted. |

### 15.11 EventProcessor — Receipt Ingestion Tests

| # | Test Name | Description |
|---|-----------|-------------|
| RC01 | `receipt_nonTransferable_valid` | Non-transferable receipt with valid cigar → stored. |
| RC02 | `receipt_witness_valid` | Witness receipt with valid indexed sig → stored in wigs. |
| RC03 | `receipt_transferable_valid` | Transferable receipt with valid sig group → stored in vrcs. |
| RC04 | `receipt_beforeEvent` | Receipt arrives before receipted event → UnverifiedReceiptError → URE escrow. |
| RC05 | `receipt_witnessBeforeEvent` | Witness receipt before event → UWE escrow. |
| RC06 | `receipt_transferableBeforeEvent` | Trans receipt before event → VRE escrow. |
| RC07 | `receipt_staleReceipt` | Receipt for old event → accepted (idempotent accumulation). |

### 15.12 Escrow System Tests

| # | Test Name | Description |
|---|-----------|-------------|
| E01 | `escrow_OOE_entryOnOutOfOrder` | Out-of-order event enters OOE escrow. |
| E02 | `escrow_OOE_resolvedWhenPriorArrives` | Prior event arrives → resolveEscrows → OOE event accepted. |
| E03 | `escrow_OOE_timeout` | OOE entry times out → removed from escrow + query domain event. |
| E04 | `escrow_PSE_entryOnPartialSigs` | Insufficient sigs → PSE escrow entry. |
| E05 | `escrow_PSE_resolvedWhenSigsAccumulate` | Additional sigs arrive → resolveEscrows → threshold met → accepted. |
| E06 | `escrow_PSE_timeout` | PSE entry times out → removed. |
| E07 | `escrow_PWE_entryOnPartialWitness` | Insufficient witness sigs → PWE escrow entry. |
| E08 | `escrow_PWE_resolvedWhenWitnessSigsArrive` | Witness sigs accumulate → resolveEscrows → TOAD met → accepted. |
| E09 | `escrow_PWE_timeout` | PWE entry times out → removed. |
| E10 | `escrow_PDE_entryOnMissingDelegation` | Missing delegation seal → PDE escrow entry. |
| E11 | `escrow_PDE_resolvedWhenDelegatorAnchors` | Delegator anchors seal → resolveEscrows → accepted. |
| E12 | `escrow_PDE_timeout` | PDE entry times out → removed. |
| E13 | `escrow_MFE_entryOnProvenanceMismatch` | Remote event for local ID → MFE escrow entry. |
| E14 | `escrow_MFE_resolvedWhenLocalSourceProvided` | Same event arrives from local source → accepted. |
| E15 | `escrow_UWE_entryBeforeEvent` | Witness receipt before event → UWE escrow. |
| E16 | `escrow_UWE_resolvedWhenEventArrives` | Receipted event arrives → resolveEscrows → receipt stored. |
| E17 | `escrow_URE_entryBeforeEvent` | Non-trans receipt before event → URE escrow. |
| E18 | `escrow_URE_resolvedWhenEventArrives` | Event arrives → resolveEscrows → receipt stored. |
| E19 | `escrow_VRE_entryBeforeEvent` | Trans receipt before event → VRE escrow. |
| E20 | `escrow_VRE_resolvedWhenEventArrives` | Event arrives → resolveEscrows → receipt stored. |
| E21 | `escrow_LDE_entryOnDuplicity` | Different SAID at same sn → LDE escrow. |
| E22 | `escrow_LDE_persists` | LDE entries are tracked for duplicity evidence. |
| E23 | `escrow_delegable_entryOnPendingApproval` | Local delegator hasn't anchored → delegable escrow. |
| E24 | `escrow_delegable_resolvedWhenApproved` | Delegator anchors → resolveEscrows → accepted. |
| E25 | `escrow_processingOrder` | Verify escrow processing order: OOE→UWE→URE→VRE→PDE→PWE→PSE→LDE. Earlier resolution unblocks later. |
| E26 | `escrow_cascadeResolution` | OOE resolved → unblocks PWE → unblocks acceptance. Multi-stage cascade in single resolveEscrows call. |
| E27 | `escrow_idempotentEntry` | Re-escrowing same event is idempotent (no duplicates). |
| E28 | `escrow_cleanupOnInvalid` | Invalid event discovered during escrow processing → removed, not re-escrowed. |

### 15.13 Domain Event (Cue) Tests

| # | Test Name | Description |
|---|-----------|-------------|
| DE01 | `domainEvent_receiptOnInception` | Successful inception → EventAccepted domain event with receipt kin. |
| DE02 | `domainEvent_receiptOnRotation` | Successful rotation → EventAccepted. |
| DE03 | `domainEvent_noticeOnIndirectMode` | Indirect mode (directMode=false) → EventNoticed instead of EventAccepted. |
| DE04 | `domainEvent_witnessForLocallyWitnessed` | Locally witnessed event → WitnessReceiptNeeded. |
| DE05 | `domainEvent_queryOnEscrowTimeout` | Escrow timeout → EventQueryNeeded with prefix and sn. |
| DE06 | `domainEvent_cloneMismatch` | Replay mode: fn mismatch → CloneMismatchDetected. |
| DE07 | `domainEvent_busOrdering` | Multiple domain events → FIFO ordering preserved in bus. |
| DE08 | `domainEvent_busDrain` | Pull all events from bus → bus empty. |

### 15.14 EventRepository Interface Compliance Tests

These tests MUST be runnable against ANY EventRepository implementation (in-memory, LMDB, SQL, DynamoDB, etc.).

| # | Test Name | Description |
|---|-----------|-------------|
| RP01 | `repo_storeAndRetrieveEvent` | Store event → retrieve by (pre, dig) → matches. |
| RP02 | `repo_storeEventIdempotent` | Store same event twice → no error, retrieve returns same. |
| RP03 | `repo_retrieveNonexistent` | Retrieve event not stored → returns None. |
| RP04 | `repo_eventLogOrdering` | Append multiple digests at sequential sn → getLastEventDigest returns last. |
| RP05 | `repo_eventLogBackwardIteration` | iterateEventLogBackward returns events in reverse sn order. |
| RP06 | `repo_firstSeenLogAppend` | appendToFirstSeenLog returns monotonically increasing ordinals. |
| RP07 | `repo_firstSeenOrdinalRoundtrip` | Store fn → retrieve fn → matches. |
| RP08 | `repo_signatureAccumulation` | Store sigs → store more sigs → retrieve returns union. |
| RP09 | `repo_witnessSignatureAccumulation` | Same as sigs but for witness signatures. |
| RP10 | `repo_nonTransReceiptStorage` | Store and retrieve (Prefixer, Cigar) couples. |
| RP11 | `repo_transReceiptStorage` | Store and retrieve (Prefixer, Number, Diger, Siger) quadruples. |
| RP12 | `repo_datetimeStorage` | Store and retrieve Dater by (pre, dig). |
| RP13 | `repo_provenanceStorage` | Store and retrieve EventProvenance. |
| RP14 | `repo_delegationSealStorage` | Store, retrieve, and remove delegation seal. |
| RP15 | `repo_witnessStateStorage` | Store and retrieve witness list at establishment event. |
| RP16 | `repo_keyStateSnapshotRoundtrip` | Store KeyStateSnapshot → retrieve → all fields match. |
| RP17 | `repo_escrowAddIterRemove` | For EACH of 10 escrow types: add → iterate → verify present → remove → verify gone. |
| RP18 | `repo_escrowIdempotentAdd` | Add same escrow entry twice → iterate returns one entry. |
| RP19 | `repo_findSealingEvent` | Walk KEL to find event containing specific seal. |
| RP20 | `repo_concurrentAccess` | Multiple IdentifierStates reading/writing same repository → no corruption. |

### 15.15 Configuration and Mode Tests

| # | Test Name | Description |
|---|-----------|-------------|
| C01 | `config_promiscuousAcceptsAll` | promiscuous=true → events for any AID accepted. |
| C02 | `config_nonPromiscuousRejectsUnknown` | promiscuous=false → events for non-local AIDs rejected. |
| C03 | `config_defaultLocalProtectsOwnedAIDs` | defaultLocal=true → misfit check applies for remote events. |
| C04 | `config_replayModeUsesAttachedTimestamps` | replayMode=true → uses firner/dater from attachments, not current time. |
| C05 | `config_replayModeDetectsMismatch` | replayMode=true + fn mismatch → CloneMismatchDetected domain event. |
| C06 | `config_directModeProducesReceipts` | directMode=true → EventAccepted domain events produced. |
| C07 | `config_indirectModeProducesNotices` | directMode=false → EventNoticed domain events instead. |
| C08 | `config_readOnlySkipsNonIdempotent` | readOnly=true → no FEL appends, no timestamp pins. Used for re-initialization from existing KEL. |
| C09 | `config_establishmentOnlyRejectsInteraction` | EO trait → interaction events rejected. |
| C10 | `config_doNotDelegateRejectsDelegation` | DND trait → delegation requests rejected. |

### 15.16 State Snapshot and Restore Tests

| # | Test Name | Description |
|---|-----------|-------------|
| SR01 | `snapshot_afterInception` | Snapshot after inception → all fields match state. |
| SR02 | `snapshot_afterRotation` | Snapshot after rotation → keys, witnesses, thresholds updated. |
| SR03 | `snapshot_afterInteraction` | Snapshot after interaction → sn updated, keys unchanged. |
| SR04 | `restore_fromSnapshot` | Create IdentifierState from snapshot → state matches original. |
| SR05 | `restore_thenApplyEvent` | Restore from snapshot → apply next event → state consistent. |
| SR06 | `snapshot_delegatedIdentifier` | Snapshot includes delegator prefix and delegation flag. |
| SR07 | `snapshot_establishmentDetail` | EstablishmentDetail (ee field) correctly tracks last est event. |

### 15.17 Integration / Lifecycle Tests

| # | Test Name | Description |
|---|-----------|-------------|
| L01 | `lifecycle_inceptionRotationInteraction` | Full sequence: inception → rotation → interaction. Verify state at each step. |
| L02 | `lifecycle_multipleRotations` | Inception → rot1 → rot2 → rot3. Verify key state evolves correctly. |
| L03 | `lifecycle_interactionBetweenRotations` | icp → ixn → rot → ixn → rot. Verify interleaving works. |
| L04 | `lifecycle_delegatedFull` | Delegated inception → delegated rotation → interaction. Both delegator and delegate KELs. |
| L05 | `lifecycle_nonTransferableComplete` | Non-transferable: inception → interaction only (no rotation possible). |
| L06 | `lifecycle_witnessedIdentifier` | Inception with 3 witnesses, TOAD=2 → rotation adding witness → rotation cutting witness. |
| L07 | `lifecycle_multipleIdentifiers` | Process events for 3 independent AIDs through same EventProcessor. |
| L08 | `lifecycle_receiptFlow` | Inception → receipt from validator → verify receipt stored. |
| L09 | `lifecycle_outOfOrderResolution` | Receive rot(sn=2) → ixn(sn=1 is missing) → OOE → receive ixn(sn=1) → resolveEscrows → both accepted. |
| L10 | `lifecycle_recoveryRotation` | icp → ixn(sn=1) → recovery rot(sn=1) supersedes ixn. Verify state reflects rotation. |
| L11 | `lifecycle_fullEscrowCascade` | Complex scenario: out-of-order + partial sigs + partial witness → events arrive incrementally → resolveEscrows eventually accepts all. |
| L12 | `lifecycle_replayFromScratch` | Build KEL of 10 events → replay all through fresh EventProcessor in replayMode → identical state. |
| L13 | `lifecycle_snapshotRestoreReplay` | Process 5 events → snapshot → restore → process 5 more → same result as processing all 10. |
| L14 | `lifecycle_cbor_msgpack_interop` | Create event in JSON → process. Create same logical event in CBOR → different SAID but same key state transitions. |

### 15.18 Test Summary

| Category | Count | Coverage |
|----------|-------|----------|
| Event Builders | 22 | All 6 builder types, defaults, auto-digest, build-time validation, SAID, multi-format |
| Seal Builders | 8 | All 7 seal types, composability |
| SignedEvent + KeyState View | 13 | Signing, field mapping, derived booleans, fluent chain, escrow query |
| Inception Validation | 17 | All inception invariants, config traits, non-transferable |
| Rotation Validation | 21 | All rotation invariants, witness ops, pre-rotation commitment |
| Interaction Validation | 7 | All interaction invariants, EO mode |
| Delegation Validation | 8 | Inception/rotation delegation, superseding rules |
| Signature Verification | 13 | Simple/weighted/BFT thresholds |
| Authorization Pipeline | 12 | Full authorization flow, provenance checks |
| Event Processor Ingestion | 11 | Dispatch, duplicity, out-of-order, recovery |
| Receipt Ingestion | 7 | 3 receipt types, before/after event |
| Escrow System | 28 | All 10 escrow types: entry, resolution, timeout, cascade |
| Domain Events | 8 | All 6 event types, ordering, bus behavior |
| Repository Compliance | 20 | All storage operations, idempotency, concurrency |
| Configuration/Modes | 10 | All 5 config flags |
| Snapshot/Restore | 7 | Roundtrip, delegation, lifecycle continuity |
| Integration/Lifecycle | 14 | Full flows, multi-AID, recovery, replay |
| **Total** | **228** | **Every public API surface, builder, view, invariant, escrow, error path** |

---

## Appendix A: Usage Examples

### A.1 Full Lifecycle — Build, Sign, Ingest

```
# Setup
repository = InMemoryEventRepository()
bus = DomainEventBus()
config = ProcessorConfig(promiscuous=true, directMode=true)
processor = EventProcessor(repository, bus, config)

# 1. Inception
event = InceptionBuilder()
    .signing_keys([k1.qb64])
    .next_keys([n1.qb64])
    .build()

signed = event.sign_with([signer1])
processor.ingestEvent(signed.event, signed.signatures)

# Verify
state = processor.identifiers[event.pre]
ks = state.keyState()
assert ks.sequence_number == 0
assert ks.signing_keys == [k1.qb64]
assert ks.is_transferable == true

# 2. Rotation (fluent from KeyState)
signed_rot = ks
    .prepare_rotation()
    .signing_keys([k2.qb64])
    .next_keys([n2.qb64])
    .build()
    .sign_with([signer2])

processor.ingestEvent(signed_rot.event, signed_rot.signatures)
ks2 = state.keyState()
assert ks2.sequence_number == 1
assert ks2.signing_keys == [k2.qb64]

# 3. Interaction (fluent from KeyState)
signed_ixn = ks2
    .prepare_interaction()
    .anchored_seals([DigestSeal.of(data_digest)])
    .build()
    .sign_with([signer2])

processor.ingestEvent(signed_ixn.event, signed_ixn.signatures)
ks3 = state.keyState()
assert ks3.sequence_number == 2
assert ks3.signing_keys == [k2.qb64]  # unchanged

# 4. Check domain events
events = bus.drain()
assert len(events) == 3
assert all(e is EventAccepted for e in events)
```

### A.2 Delegated Inception with Seal Anchoring

```
# Delegator creates inception first
delegator_icp = InceptionBuilder()
    .signing_keys([dk1.qb64])
    .next_keys([dn1.qb64])
    .build()

processor.ingestEvent(delegator_icp.sign_with([d_signer]).event, ...)

# Delegate creates delegated inception
delegate_icp = DelegatedInceptionBuilder()
    .signing_keys([ek1.qb64])
    .next_keys([en1.qb64])
    .delegator(delegator_icp.pre)
    .build()

# Delegator anchors approval seal via interaction
anchor = processor.identifiers[delegator_icp.pre].keyState()
    .prepare_interaction()
    .anchored_seals([EventSeal.of(delegate_icp.pre, 0, delegate_icp.said)])
    .build()
    .sign_with([d_signer])

processor.ingestEvent(anchor.event, anchor.signatures)

# Now ingest the delegated inception with delegation seal reference
processor.ingestEvent(
    delegate_icp,
    delegate_sigs,
    delegatorSeqNum=1,       # sn of the anchoring interaction
    delegatorDigest=anchor.event.said
)
```

### A.3 Out-of-Order Escrow Resolution

```
# Receive rotation at sn=2 before interaction at sn=1
rot2 = ...  # rotation event at sn=2
processor.ingestEvent(rot2, rot2_sigs)
# → OutOfOrderError → OOE escrow

# Query escrow state
pending = escrows.pending_for(rot2.pre)
assert len(pending) == 1
assert pending[0].reason == EscrowReason.OUT_OF_ORDER

# Now the missing interaction at sn=1 arrives
ixn1 = ...  # interaction event at sn=1
processor.ingestEvent(ixn1, ixn1_sigs)
# → accepted normally

# Resolve escrows
processor.resolveEscrows()
# → OOE sweep finds rot2, prior now exists, re-validates → accepted

ks = processor.identifiers[rot2.pre].keyState()
assert ks.sequence_number == 2
```

### A.4 Snapshot, Restore, Continue

```
# Process events and snapshot
processor.ingestEvent(icp, icp_sigs)
processor.ingestEvent(rot, rot_sigs)

state = processor.identifiers[prefix]
snapshot = state.snapshot()

# Later: restore from snapshot
new_repo = InMemoryEventRepository()
# (assume events and sigs are already in new_repo from replication)
restored = IdentifierState.fromSnapshot(snapshot, new_repo)

# Continue from restored state
next_ixn = restored.keyState()
    .prepare_interaction()
    .anchored_seals([DigestSeal.of(data_digest)])
    .build()
    .sign_with([current_signer])

# Verify continuity
assert next_ixn.event.sn == snapshot.s + 1
assert next_ixn.event.p == snapshot.d
```

### A.5 Non-Transferable Inception

```
event = InceptionBuilder()
    .signing_keys([k1.qb64])
    .non_transferable()    # type-narrows: removes .next_keys(), .witnesses(), etc.
    .build()

signed = event.sign_with([signer1])
processor.ingestEvent(signed.event, signed.signatures)

ks = processor.identifiers[event.pre].keyState()
assert ks.is_transferable == false
assert ks.next_key_digests == []
assert ks.witnesses == []

# Attempting rotation would fail
# processor.ingestEvent(rot_event, rot_sigs)  → ValidationError
```

---

## Appendix B: DDD Name Mapping

Complete mapping between keripy implementation names and DDD domain names used in this specification.

### Type Names

| keripy Name | DDD Domain Name | DDD Pattern |
|---|---|---|
| `Kever` | **IdentifierState** | Aggregate Root |
| `Kevery` | **EventProcessor** | Domain Service |
| `Baser` / `KelStore` | **EventRepository** | Repository Interface |
| `CueDeck` | **DomainEventBus** | Domain Event Publisher |
| `Cue` | **DomainEvent** | Domain Event (Value Object) |
| `KeyStateRecord` | **KeyStateSnapshot** | Value Object |
| `EventSourceRecord` | **EventProvenance** | Value Object |
| `LastEstLoc` | **EstablishmentLocator** | Value Object |
| `StateEERecord` | **EstablishmentDetail** | Value Object |

### Method Names

| keripy Method | DDD Method | Context |
|---|---|---|
| `Kever.update()` | `IdentifierState.applyEvent()` | Apply non-inception event |
| `Kever.incept()` | `IdentifierState.validateInception()` | Validate inception fields |
| `Kever.rotate()` | `IdentifierState.validateRotation()` | Validate rotation constraints |
| `Kever.valSigsWigsDel()` | `IdentifierState.validateAuthorization()` | Verify sigs + witnesses + delegation |
| `Kever.validateDelegation()` | `IdentifierState.validateDelegation()` | Check delegator anchor seal |
| `Kever.logEvent()` | `IdentifierState.commitEvent()` | Persist event to repository |
| `Kever.state()` | `IdentifierState.snapshot()` | Export current key state |
| `Kever.reload()` | `IdentifierState.restore()` | Reload from snapshot |
| `Kever.exposeds()` | `IdentifierState.extractPriorNextIndices()` | Get exposed prior-next key indices |
| `Kever.deriveBacks()` | `IdentifierState.deriveWitnessList()` | Compute witness list from cuts/adds |
| `Kevery.processEvent()` | `EventProcessor.ingestEvent()` | Main event entry point |
| `Kevery.processReceipt()` | `EventProcessor.ingestReceipt()` | Handle receipt messages |
| `Kevery.processEscrows()` | `EventProcessor.resolveEscrows()` | Periodic escrow sweep |

---

## Appendix C: Wire-Format Field Reference

Quick reference for KERI event wire-format fields as used by builders and views.

### Inception Event Fields (ilk: `icp` / `dip`)

| Field | Name | Type | Description |
|-------|------|------|-------------|
| `v` | version | str | Protocol version string |
| `t` | type | str | Event ilk (`"icp"` or `"dip"`) |
| `d` | digest | str | SAID of this event |
| `i` | identifier | str | AID prefix (= SAID for self-addressing) |
| `s` | sequence | str | Sequence number (`"0"` for inception) |
| `kt` | key threshold | str or list | Signing threshold |
| `k` | keys | list[str] | Signing public keys |
| `nt` | next threshold | str or list | Next key threshold |
| `n` | next digests | list[str] | Next key digests |
| `bt` | backer threshold | str | Witness threshold (TOAD) |
| `b` | backers | list[str] | Witness prefixes |
| `c` | config | list[str] | Configuration traits |
| `a` | anchors | list[dict] | Anchor seals |
| `di` | delegator | str | Delegator prefix (`dip` only) |

### Rotation Event Fields (ilk: `rot` / `drt`)

| Field | Name | Type | Description |
|-------|------|------|-------------|
| `v` | version | str | Protocol version string |
| `t` | type | str | Event ilk (`"rot"` or `"drt"`) |
| `d` | digest | str | SAID of this event |
| `i` | identifier | str | AID prefix |
| `s` | sequence | str | Sequence number |
| `p` | prior | str | Prior event SAID |
| `kt` | key threshold | str or list | New signing threshold |
| `k` | keys | list[str] | New signing public keys |
| `nt` | next threshold | str or list | New next key threshold |
| `n` | next digests | list[str] | New next key digests |
| `bt` | backer threshold | str | New witness threshold |
| `br` | backer removes | list[str] | Witnesses to remove (cuts) |
| `ba` | backer adds | list[str] | Witnesses to add |
| `c` | config | list[str] | Configuration traits |
| `a` | anchors | list[dict] | Anchor seals |

### Interaction Event Fields (ilk: `ixn`)

| Field | Name | Type | Description |
|-------|------|------|-------------|
| `v` | version | str | Protocol version string |
| `t` | type | str | `"ixn"` |
| `d` | digest | str | SAID of this event |
| `i` | identifier | str | AID prefix |
| `s` | sequence | str | Sequence number |
| `p` | prior | str | Prior event SAID |
| `a` | anchors | list[dict] | Anchor seals |

### Receipt Fields (ilk: `rct`)

| Field | Name | Type | Description |
|-------|------|------|-------------|
| `v` | version | str | Protocol version string |
| `t` | type | str | `"rct"` |
| `d` | digest | str | SAID of receipted event |
| `i` | identifier | str | Prefix of receipted AID |
| `s` | sequence | str | Sequence number of receipted event |
