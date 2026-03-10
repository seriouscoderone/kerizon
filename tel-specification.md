# TEL: Transaction Event Log Specification

**Version:** 0.3.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification for a Transaction Event Log — an
append-only, content-addressed state machine that tracks the lifecycle of
issued artifacts (credentials, tokens, permits, or any uniquely-identified
datum). Designed to be self-contained, with pluggable interfaces for trust
anchoring, signature verification, and storage.

**Dependencies:** [SAID Specification](./said-specification.md) for content
addressing and digest computation.

---

## Table of Contents

1. [What Problem Does TEL Solve?](#1-what-problem-does-tel-solve)
2. [Core Concepts](#2-core-concepts)
3. [Architecture Overview](#3-architecture-overview)
4. [Registry Events](#4-registry-events)
5. [Credential Events](#5-credential-events)
6. [State Machine](#6-state-machine)
7. [Witness Model](#7-witness-model)
8. [Anchor Binding](#8-anchor-binding)
9. [Escrow and Recovery](#9-escrow-and-recovery)
10. [State Records](#10-state-records)
11. [Verification Pipeline](#11-verification-pipeline)
12. [Storage Interface](#12-storage-interface)
13. [External Dependency Interfaces](#13-external-dependency-interfaces)
14. [Developer API](#14-developer-api)
15. [Invariants](#15-invariants)
16. [Security Considerations](#16-security-considerations)
17. [Reference Examples](#17-reference-examples)

---

## 1. What Problem Does TEL Solve?

You have issued a credential — a diploma, a license, an access token. Later
you need to revoke it. The holder still has the original bytes. How does a
verifier know the credential is no longer valid?

You need a **tamper-evident, append-only log** that records:
- *When* the credential was issued (and by whom)
- *Whether* it has been revoked (and when)
- *Who* is authorized to attest to these state changes

TEL provides exactly this. It is a content-addressed event log where each
event is a SAD (Self-Addressing Data structure with an embedded SAID), events
are chained by digest, and the current state is derived by replaying the log.

TEL does NOT:
- Store credential content (it tracks state, not data)
- Define credential structure (that is the credential format's concern)
- Manage keys or identities (that is the trust layer's concern)
- Define exchange protocols (that is the presentation layer's concern)

TEL is a general-purpose transaction ordering system. This specification focuses on its use for credential lifecycle tracking, but the underlying event log mechanism can be applied to any domain requiring tamper-evident, append-only state tracking.

TEL answers one question: **is this artifact currently valid?**

---

## 2. Core Concepts

### 2.1 Terminology

| Term | Definition |
|------|-----------|
| **Transaction** | Any state-changing operation recorded in an event log. In general, a transaction is any ordered, committed change. In this specification, transactions are specialized to credential lifecycle operations (issuance, revocation), but the mechanism is domain-agnostic. |
| **TEL** | Transaction Event Log. An append-only sequence of content-addressed events tracking the lifecycle state of one or more artifacts. |
| **Registry** | A governance container for a group of artifacts. Defines the trust configuration (who can attest, what threshold of agreement is required). |
| **Credential** | Any uniquely-identified artifact whose lifecycle TEL tracks. Identified by its SAID. |
| **Event** | A content-addressed (SAIDed) ordered map appended to a TEL. Each event references its predecessor by digest. |
| **Witness** | An independent party that co-signs TEL events, providing fault tolerance and accountability. Analogous to a notary who attests to the event. |
| **Management TEL** | The registry event chain (`vcp`/`vrt` events) that governs witness configuration and authorization policy for a group of credentials. |
| **VC TEL** | A per-credential event chain (`iss`/`rev` or `bis`/`brv` events) that tracks the lifecycle of a single credential. Each VC TEL references its Management TEL via `ri` or `ii`. |
| **Anchor** | A cryptographic binding from a TEL event to an external trust source (e.g., a key event log, a blockchain, a timestamp authority). Proves authorization. |
| **Seal** | The anchor's representation inside the trust source — a digest reference embedded in the trust source's own log that points to the TEL event. |
| **Registry Anchor** | A reference from a credential event to a specific registry event, binding the credential operation to a known witness configuration. |
| **Escrow** | Temporary storage for events that cannot yet be fully verified (missing anchor, insufficient signatures, out-of-order arrival). |

### 2.2 Dependency Graph

```
TEL depends on:
  ├── SAID (content addressing, digest computation, placeholder protocol)
  ├── Deterministic serialization (JSON, CBOR, or MessagePack)
  └── An ordered, append-only storage mechanism

TEL optionally depends on (via pluggable interfaces):
  ├── An anchor verifier (validates trust binding)
  ├── A signature verifier (validates witness attestations)
  └── An identity resolver (maps identifiers to verification material)

TEL does NOT depend on:
  ├── Any specific identity system
  ├── Any specific credential format
  ├── Any specific network protocol
  └── Any specific database technology

Cross-references to companion specifications:
  ├── [KEL Crypto](kel-crypto.md) — provides SAID and serialization (Primitives)
  ├── [KEL Core](kel-core.md) — provides KeyStateProvider (used by KERI anchor implementation)
  └── [ACDC Verification](acdc-verification.md) — consumes CredentialStatus from TEL
```

---

## 3. Architecture Overview

TEL operates with two types of event chains:

- **Management TEL** (registry chain) — a single chain of `vcp`/`vrt` events that governs witness configuration and authorization policy.
- **VC TEL** (per-credential chain) — one chain per credential of `iss`/`rev` or `bis`/`brv` events that tracks credential lifecycle. Each VC TEL references its Management TEL via the `ri` (registry identifier) or `ii` field.

These chains work together as two parallel event chains per registry:

```
Registry Chain (governance):
  ┌─────┐    ┌─────┐    ┌─────┐
  │ RIC │───→│ RRO │───→│ RRO │───→ ...
  │sn=0 │    │sn=1 │    │sn=2 │
  └─────┘    └─────┘    └─────┘
  inception   rotation   rotation

Credential Chains (per credential, lifecycle):
  ┌─────┐    ┌─────┐
  │ ISS │───→│ REV │    (credential A)
  │sn=0 │    │sn=1 │
  └─────┘    └─────┘

  ┌─────┐                (credential B — still active)
  │ ISS │
  │sn=0 │
  └─────┘

  ┌─────┐    ┌─────┐
  │ ISS │───→│ REV │    (credential C)
  │sn=0 │    │sn=1 │
  └─────┘    └─────┘
```

**Registry chain:** Manages the witness roster and configuration. A single
sequence (0, 1, 2, ...) of registry events.

**Credential chains:** One per credential, each with at most two events:
issuance (sn=0) and revocation (sn=1). Each credential chain is bound to
the registry that governs it.

### 3.1 Two Operating Modes

| Mode | Registry Trait | Credential Events | Witness Signatures | Use Case |
|------|---------------|-------------------|-------------------|----------|
| **Simple** (witnessless) | `NB` | `iss`, `rev` | Not required | Single-authority revocation |
| **Witnessed** | (default) | `bis`, `brv` | Required (threshold) | Distributed attestation |

The mode is fixed at registry inception and cannot change.

---

## 4. Registry Events

Registry events manage the governance configuration of a TEL. They form a
single chain per registry.

### 4.1 Registry Inception (RIC)

Creates a new registry. This is always the first event (sn=0).

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"vcp"` |
| 2 | `d` | SAID | MUST | SAID of this event (self-addressing) |
| 3 | `i` | SAID | MUST | Registry identifier. Derived from this event's SAID. Equals `d` at inception. |
| 4 | `ii` | Identifier | MUST | Issuer identifier — the controller of this registry |
| 5 | `s` | HexString | MUST | Sequence number. Always `"0"` at inception. |
| 6 | `c` | List[String] | MUST | Configuration traits. May be empty `[]`. |
| 7 | `bt` | HexString | MUST | Witness threshold — minimum number of witness signatures required |
| 8 | `b` | List[Identifier] | MUST | Initial witness list. May be empty `[]`. |
| 9 | `n` | Nonce | MUST | Cryptographic nonce — provides uniqueness for registry identifier derivation |

**Constraints:**
- `s` MUST be `"0"`.
- `i` equals `d` (the registry is identified by its inception event's SAID).
- If `"NB"` (No dedicated Witnesses) is in `c`, then `b` MUST be empty and `bt` MUST be `"0"`.
- If `"NB"` is NOT in `c`, then `bt` MUST satisfy `1 <= int(bt, 16) <= len(b)`.
- Witnesses in `b` MUST be unique (no duplicates).
- `n` MUST be a cryptographically random value of sufficient entropy (minimum 128 bits).

### 4.2 Registry Rotation (RRO)

Modifies the witness roster. This is any subsequent registry event (sn >= 1).

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"vrt"` |
| 2 | `d` | SAID | MUST | SAID of this event |
| 3 | `i` | Identifier | MUST | Registry identifier. MUST equal the registry's inception `i`. |
| 4 | `p` | SAID | MUST | Prior event digest. MUST equal the prior event's `d` field. |
| 5 | `s` | HexString | MUST | Sequence number. MUST equal `prior_sn + 1`. |
| 6 | `bt` | HexString | MUST | New witness threshold |
| 7 | `br` | List[Identifier] | MUST | Witnesses removed (cuts). May be empty `[]`. |
| 8 | `ba` | List[Identifier] | MUST | Witnesses added. May be empty `[]`. |

**Constraints:**
- `i` MUST be invariant across all registry events.
- `p` MUST equal the SAID of the immediately prior registry event.
- `s` MUST equal `prior_sn + 1` (sequential, no gaps).
- `br` entries MUST be a subset of the current witness list.
- `ba` entries MUST NOT already be in the current witness list.
- `br` and `ba` MUST NOT intersect.
- No duplicates within `br` or within `ba`.
- New witness list = `(current_witnesses - br) ∪ ba`.
- `bt` MUST satisfy threshold rules for the new witness list.
- If registry has `NB` trait: rotation is NOT permitted.

---

## 5. Credential Events

Credential events track the issuance and revocation of individual artifacts.
Each credential has its own independent event chain, governed by the registry
it belongs to.

### 5.1 Simple Issuance (witnessless)

For registries with the `NB` trait.

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"iss"` |
| 2 | `d` | SAID | MUST | SAID of this event |
| 3 | `i` | SAID | MUST | Credential identifier — the SAID of the credential being issued |
| 4 | `s` | HexString | MUST | Sequence number. Always `"0"` for issuance. |
| 5 | `ri` | Identifier | MUST | Registry identifier — which registry governs this credential |
| 6 | `dt` | DateTimeString | SHOULD | ISO 8601 datetime of issuance. Issuer-claimed. If omitted, validator MAY use anchor event timestamp. Not cryptographically verified (see §16.6). |

**Constraints:**
- `s` MUST be `"0"`.
- `ri` MUST reference a registry with the `NB` trait.
- The credential identified by `i` MUST NOT already have an issuance event in this registry.

### 5.2 Simple Revocation (witnessless)

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"rev"` |
| 2 | `d` | SAID | MUST | SAID of this event |
| 3 | `i` | SAID | MUST | Credential identifier |
| 4 | `s` | HexString | MUST | Sequence number. Always `"1"` for revocation. |
| 5 | `ri` | Identifier | MUST | Registry identifier |
| 6 | `p` | SAID | MUST | Prior event digest. MUST equal the issuance event's `d`. |
| 7 | `dt` | DateTimeString | SHOULD | ISO 8601 datetime of revocation. Issuer-claimed. If omitted, validator MAY use anchor event timestamp. Not cryptographically verified (see §16.6). |

**Constraints:**
- `s` MUST be `"1"`.
- `p` MUST equal the SAID of the prior issuance event (`iss`).
- A credential MUST be issued (sn=0 exists) before it can be revoked.
- `ri` MUST reference a registry with the `NB` trait.

### 5.3 Witnessed Issuance

For registries WITHOUT the `NB` trait.

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"bis"` |
| 2 | `d` | SAID | MUST | SAID of this event |
| 3 | `i` | SAID | MUST | Credential identifier |
| 4 | `ii` | Identifier | MUST | Registry identifier (issuing registry) |
| 5 | `s` | HexString | MUST | Sequence number. Always `"0"`. |
| 6 | `ra` | AnchorMap | MUST | Registry anchor — binds to a specific registry state |
| 7 | `dt` | DateTimeString | SHOULD | ISO 8601 datetime of issuance. Issuer-claimed. If omitted, validator MAY use anchor event timestamp. Not cryptographically verified (see §16.6). |

**Registry Anchor (`ra`) structure:**

| Field | Type | Semantics |
|-------|------|-----------|
| `i` | Identifier | Registry identifier |
| `s` | HexString | Sequence number of the referenced registry event |
| `d` | SAID | SAID of the referenced registry event |

**Constraints:**
- `s` MUST be `"0"`.
- `ra` MUST reference a valid registry event.
- The referenced registry event determines which witnesses and threshold apply.
- Witness signatures on this event MUST meet the threshold defined by the referenced registry state.

### 5.4 Witnessed Revocation

**Fields:**

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol, version, serialization kind, size |
| 1 | `t` | String | MUST | Event type. Value: `"brv"` |
| 2 | `d` | SAID | MUST | SAID of this event |
| 3 | `i` | SAID | MUST | Credential identifier |
| 4 | `s` | HexString | MUST | Sequence number. Always `"1"`. |
| 5 | `p` | SAID | MUST | Prior event digest |
| 6 | `ra` | AnchorMap | MUST | Registry anchor |
| 7 | `dt` | DateTimeString | SHOULD | ISO 8601 datetime of revocation. Issuer-claimed. If omitted, validator MAY use anchor event timestamp. Not cryptographically verified (see §16.6). |

**Constraints:**
- `s` MUST be `"1"`.
- `p` MUST equal the SAID of the prior issuance event (`bis`).
- `ra` MUST reference a valid registry event.
- Witness signatures MUST meet threshold.

---

## 6. State Machine

### 6.1 Registry State Machine

```
                    ┌──────────────────────────────┐
                    │                              │
                    v                              │
  ┌──────────┐   ┌──────────┐   ┌──────────┐     │
  │   vcp    │──→│   vrt    │──→│   vrt    │──→ ...
  │  sn = 0  │   │  sn = 1  │   │  sn = 2  │
  └──────────┘   └──────────┘   └──────────┘
   inception      rotation       rotation
```

**Rules:**
- Inception (`vcp`) MUST be sn=0. Exactly one per registry.
- Rotation (`vrt`) MUST be sn = prior_sn + 1. Zero or more.
- Each event's `p` field chains to the prior event's `d`.
- Registry identifier `i` is invariant across all events.
- If `NB` trait is set at inception, rotation is forbidden.

### 6.2 Credential State Machine

```
  ┌──────────┐         ┌──────────┐
  │iss / bis │────────→│rev / brv │
  │  sn = 0  │         │  sn = 1  │
  │ (issued) │         │(revoked) │
  └──────────┘         └──────────┘
```

**Rules:**
- Issuance (`iss` or `bis`) MUST be sn=0. Exactly one per credential.
- Revocation (`rev` or `brv`) MUST be sn=1. At most one per credential.
- Revocation's `p` field MUST chain to the issuance event's `d`.
- A credential MUST be issued before it can be revoked.
- A credential CANNOT be issued twice (duplicate issuance is an error).
- Once revoked, a credential CANNOT be un-revoked.

### 6.3 Credential States

| State | Condition | Meaning |
|-------|-----------|---------|
| **Not Issued** | No events exist for this credential SAID | Credential is unknown to this registry |
| **Issued** | Issuance event exists (sn=0), no revocation | Credential is active and valid |
| **Revoked** | Both issuance (sn=0) and revocation (sn=1) exist | Credential is no longer valid |

### 6.4 Event Type / Mode Compatibility

| Registry Mode | Issuance Event | Revocation Event |
|---------------|---------------|-----------------|
| Simple (witnessless) | `iss` | `rev` |
| Witnessed | `bis` | `brv` |

Using a simple event type (`iss`/`rev`) against a witnessed registry, or vice
versa, is a validation error.

---

## 7. Witness Model

Witnesses are independent parties that co-sign TEL events. They provide:

1. **Fault tolerance** — the registry state is attested by multiple parties.
2. **Accountability** — witnesses can be held responsible for conflicting attestations.
3. **Threshold security** — an attacker must compromise `threshold` witnesses
   to forge a state change.

### 7.1 Witness Configuration

Defined at registry inception (`vcp`) and modifiable via rotation (`vrt`):

```
witness_list: [identifier_1, identifier_2, ..., identifier_n]
threshold:    t    (where 1 <= t <= n)
```

A TEL event is **fully witnessed** when at least `threshold` distinct witnesses
have provided valid signatures on the event.

### 7.2 Witness Rotation

Registry rotation (`vrt`) modifies the witness list through cuts and adds:

```
new_witnesses = (current_witnesses - cuts) ∪ adds
```

The rotation event itself carries the new threshold. Credential events issued
after a rotation are validated against the new witness configuration.

### 7.3 Witnessless Mode

When the `NB` trait is set at inception:
- No witnesses are configured (`b = []`, `bt = "0"`).
- No witness signatures are required on credential events.
- Authorization relies solely on the trust anchor (e.g., the issuer's key
  event log).
- Registry rotation is not permitted.
- Simpler but offers no distributed attestation.

### 7.4 Indexed Signatures

Witness signatures are **indexed** — each signature carries the index of the
witness in the witness list that produced it. This allows efficient verification:

```
signatures: [(index_0, signature_0), (index_2, signature_2), ...]
```

The verifier checks:
1. Each index maps to a valid witness in the current list.
2. Each signature verifies against that witness's public key.
3. The number of unique valid indices >= threshold.

---

## 8. Anchor Binding

TEL events do not carry their own authorization. Instead, they are
**anchored** to an external trust source that provides cryptographic proof
of authorization. The anchor mechanism is pluggable.

### 8.1 What an Anchor Proves

An anchor proves that the controller of the registry authorized a specific
TEL event at a specific point in time. Without a valid anchor, a TEL event
is held in escrow.

### 8.2 Seal Structure

The anchor is bidirectional:

**In the trust source** (e.g., a key event log interaction event):
```
seal = {
    "i": <TEL event identifier>,
    "s": <TEL event sequence number>,
    "d": <TEL event SAID>
}
```

**In the TEL event** (provided during processing):
```
anchor_proof = {
    "sn": <trust source event sequence number>,
    "said": <trust source event SAID>
}
```

The verifier checks both directions: the trust source contains a seal
pointing to the TEL event, and the TEL event's anchor proof points back to
the trust source event.

**CESR Seal Attachment Codes:**

When seals are transmitted as CESR attachments (rather than embedded in the event map), the following counter codes apply:

| Counter Code | Name | Structure | Use |
|-------------|------|-----------|-----|
| `-G` | SealSourceCouples | `snu + dig` pairs | Anchoring event reference as sequence-number + digest couple |
| `-I` | SealSourceTriples | `pre + snu + dig` triples | Anchoring source event reference as prefix + sequence-number + digest triple |

Example: a `-G` attachment carrying the anchor proof for a TEL event references the trust source event by its sequence number and SAID as a couple.

### 8.3 Registry Anchor (for Witnessed Events)

Witnessed credential events (`bis`, `brv`) carry an additional anchor — the
**registry anchor** (`ra`) — that binds the credential operation to a specific
registry state:

```
ra = {
    "i": <registry identifier>,
    "s": <registry event sequence number>,
    "d": <registry event SAID>
}
```

This determines which witness list and threshold apply to the credential event.
The verifier resolves the referenced registry event and uses its witness
configuration for signature validation.

### 8.4 Anchor Verification as an Interface

TEL does not prescribe how anchors are implemented. The anchor verification
is defined as an abstract interface (see Section 13.1). Possible
implementations:

- **Key Event Log** — anchor to a KERI KEL interaction event
- **Blockchain** — anchor to a transaction with a digest commitment
- **Timestamp Authority** — anchor to a signed timestamp receipt
- **Direct Trust** — no anchor; trust the issuer's signature directly

---

## 9. Escrow and Recovery

TEL events may arrive before their dependencies are available. Rather than
rejecting these events, TEL holds them in **escrow** until the missing
dependency arrives.

### 9.1 Escrow Types

| Escrow | Trigger | Waiting For | Resolution |
|--------|---------|-------------|------------|
| **Anchorless** | Anchor verification fails or anchor not yet available | Trust source event containing the seal | Re-attempt anchor verification when new trust source events arrive |
| **Partially Witnessed** | Witness signatures present but below threshold | Additional witness signatures | Re-count signatures when new signatures arrive |
| **Out-of-Order** | Event sequence number > expected (gap in log) | Prior event(s) to fill the gap | Re-attempt processing when earlier events arrive |

### 9.2 Escrow Lifecycle

```
Event arrives
    │
    ├──→ Anchor missing?        ──→ Anchorless escrow
    ├──→ Signatures < threshold? ──→ Partially Witnessed escrow
    ├──→ Prior event missing?    ──→ Out-of-Order escrow
    └──→ All checks pass         ──→ Log event, update state
```

Each escrow stores:
- The serialized event bytes (for replay)
- The claimed anchor proof (sequence number, SAID of trust source event)
- Any witness signatures received so far

### 9.3 Escrow Processing

Escrow processors run periodically or on-demand when new information arrives:

```
function process_anchorless_escrow(trust_source_events):
    for each escrowed event:
        if anchor_verifier.verify(event, claimed_anchor):
            remove from escrow
            process event normally (may still enter other escrows)

function process_partial_witness_escrow(new_signatures):
    for each escrowed event:
        merge new signatures with existing
        if count(valid_unique_signatures) >= threshold:
            remove from escrow
            process event normally

function process_out_of_order_escrow():
    for each escrowed event (sorted by sequence number):
        if prior event now exists in log:
            remove from escrow
            process event normally
```

### 9.4 Escrow Timeout

An implementation SHOULD define a maximum escrow duration. Events held in
escrow beyond this duration SHOULD be discarded. The timeout is an
implementation choice, not specified by this protocol.

---

## 10. State Records

TEL maintains two types of state records for fast lookup without full log
replay.

### 10.1 Registry State Record

Captures the current governance state of a registry:

| Field | Type | Semantics |
|-------|------|-----------|
| `vn` | VersionTuple | Protocol version `[major, minor]` |
| `i` | Identifier | Registry identifier (inception SAID) |
| `s` | HexString | Current sequence number |
| `d` | SAID | SAID of the latest registry event |
| `ii` | Identifier | Registry controller (issuer identifier) |
| `dt` | DateTimeString | Timestamp of latest state update |
| `et` | String | Latest event type (`"vcp"` or `"vrt"`) |
| `bt` | HexString | Current witness threshold |
| `b` | List[Identifier] | Current witness list |
| `c` | List[String] | Configuration traits |

Updated after every successfully processed registry event.

### 10.2 Credential State Record

Captures the current lifecycle state of a credential:

| Field | Type | Semantics |
|-------|------|-----------|
| `vn` | VersionTuple | Protocol version `[major, minor]` |
| `i` | SAID | Credential identifier |
| `s` | HexString | Current sequence number (`"0"` = issued, `"1"` = revoked) |
| `d` | SAID | SAID of the latest credential event |
| `ri` | Identifier | Registry identifier |
| `ra` | AnchorMap | Registry anchor (empty `{}` for witnessless) |
| `a` | AnchorMap | Trust source anchor proof |
| `dt` | DateTimeString | Timestamp of latest state change |
| `et` | String | Latest event type (`"iss"`, `"bis"`, `"rev"`, or `"brv"`) |

Updated after every successfully processed credential event.

### 10.3 State Derivation

State records are a **cache** derived from the event log. An implementation
MUST be able to reconstruct any state record by replaying the log from
inception. If a state record and the log disagree, the log is authoritative.

---

## 11. Verification Pipeline

Verifying a TEL event is a multi-step pipeline. Each step can independently
succeed, fail, or defer (escrow).

### 11.1 Event Verification

```
function verify_event(event, anchor_proof, witness_signatures) -> Result:

    // Step 1: Structural validation
    assert event is a valid ordered map
    assert event.t is a recognized event type
    assert event.d == saidify(event).said              // SAID integrity

    // Step 2: Sequence validation
    if event is inceptive (sn == 0):
        assert no prior events exist for this identifier
    else:
        prior = lookup_event(event.i, event.s - 1)
        assert prior exists                             // else: Out-of-Order escrow
        assert event.p == prior.d                       // digest chain

    // Step 3: Mode compatibility
    if registry has NB trait:
        assert event.t in {iss, rev}                    // simple events only
    else:
        assert event.t in {bis, brv}                    // witnessed events only

    // Step 4: Anchor verification
    assert anchor_verifier.verify(event, anchor_proof)  // else: Anchorless escrow

    // Step 5: Witness signature verification (witnessed mode only)
    if registry does NOT have NB trait:
        registry_state = resolve_registry_state(event)
        valid_count = verify_witness_signatures(event, witness_signatures, registry_state)
        assert valid_count >= registry_state.threshold  // else: Partial Witness escrow

    // Step 6: Log event and update state
    store_event(event)
    update_state_record(event)
```

### 11.2 Credential State Query

```
function credential_state(credential_said, registry_id) -> State:
    record = lookup_credential_state(credential_said)

    if record is None:
        return NOT_ISSUED

    if record.et in {"iss", "bis"}:
        return ISSUED

    if record.et in {"rev", "brv"}:
        return REVOKED
```

---

## 12. Storage Interface

TEL requires persistent, ordered storage. The storage interface is abstract —
any implementation that satisfies these operations is valid.

### 12.1 Event Store

Stores serialized event bytes, keyed by (identifier, digest):

```
interface EventStore:
    put(identifier, digest, event_bytes) -> void
    get(identifier, digest) -> event_bytes | null
    exists(identifier, digest) -> bool
```

### 12.2 Sequence Index

Maps (identifier, sequence_number) to event digest, enabling log replay:

```
interface SequenceIndex:
    put(identifier, sequence_number, digest) -> void
    get(identifier, sequence_number) -> digest | null
    get_latest(identifier) -> (sequence_number, digest) | null
```

### 12.3 State Store

Stores current state records for fast queries:

```
interface StateStore:
    put_registry_state(registry_id, RegistryStateRecord) -> void
    get_registry_state(registry_id) -> RegistryStateRecord | null

    put_credential_state(credential_said, CredentialStateRecord) -> void
    get_credential_state(credential_said) -> CredentialStateRecord | null
```

### 12.4 Signature Store

Stores witness signatures associated with events:

```
interface SignatureStore:
    put(identifier, digest, indexed_signatures) -> void
    get(identifier, digest) -> list[IndexedSignature]
    append(identifier, digest, new_signatures) -> void   // for incremental witness
```

### 12.5 Escrow Stores

One store per escrow type. Same interface:

```
interface EscrowStore:
    put(identifier, sequence_number, digest) -> void
    get_all() -> iterator[(identifier, sequence_number, digest)]
    remove(identifier, sequence_number, digest) -> void
```

### 12.6 Witness List Store

Stores the witness roster at each registry event:

```
interface WitnessStore:
    put(registry_id, digest, witness_list) -> void
    get(registry_id, digest) -> list[Identifier]
```

---

## 13. External Dependency Interfaces

These are the abstractions that decouple TEL from any specific trust
infrastructure. An implementation MUST provide concrete implementations of
these interfaces.

### 13.1 Anchor Verifier

Validates that a TEL event is authorized by the registry controller.

```
interface AnchorVerifier:

    verify(event, anchor_proof) -> bool
        // Returns true if the trust source at the location specified
        // by anchor_proof contains a seal matching this event.
        //
        // Parameters:
        //   event:        The TEL event being verified
        //   anchor_proof: Location in the trust source (sn + said)
        //
        // A KERI implementation would:
        //   1. Look up the KEL event at (controller_aid, anchor_proof.sn)
        //   2. Check that the KEL event's seal list contains a seal
        //      where seal.i == event.i, seal.s == event.s, seal.d == event.d
        //
        // A blockchain implementation would:
        //   1. Look up the transaction at anchor_proof
        //   2. Check that it contains a digest commitment to event.d
```

### 13.2 Signature Verifier

Validates witness signatures against known verification material.

```
interface SignatureVerifier:

    verify_indexed(event_bytes, signatures, witness_list) -> list[int]
        // Returns the list of witness indices whose signatures are valid.
        //
        // Parameters:
        //   event_bytes:  The serialized event (what was signed)
        //   signatures:   List of (index, signature_bytes) pairs
        //   witness_list: Ordered list of witness identifiers
        //
        // For each (index, sig):
        //   1. Resolve witness_list[index] to a public verification key
        //   2. Verify sig against event_bytes using that key
        //   3. If valid, include index in the result
        //
        // A KERI implementation would resolve each witness identifier
        // to its current key state via KEL lookup.
```

### 13.3 Identity Resolver

Maps identifiers to verification material. Used by the signature verifier.

```
interface IdentityResolver:

    resolve(identifier) -> VerificationKey | null
        // Returns the current public key (or key set) for the given
        // identifier, or null if the identifier is unknown.
        //
        // A KERI implementation would replay the identifier's KEL
        // to derive its current key state.
        //
        // A DID implementation would resolve the DID document.
        //
        // A simple implementation might use a static key registry.

    is_non_transferable(identifier) -> bool
        // Returns true if the identifier is bound to a single key
        // that cannot be rotated. Witnesses are typically non-transferable.
```

### 13.4 Controller Authorizer

Determines whether an entity is authorized to manage a registry.

```
interface ControllerAuthorizer:

    is_controller(identifier, registry_id) -> bool
        // Returns true if the given identifier is the controller
        // of the specified registry.
        //
        // In the simplest case, this checks registry_state.ii == identifier.
        //
        // A delegation-aware implementation might also check
        // whether the identifier is a delegate of the controller.
```

### 13.5 Composing the Interfaces

A complete TEL processor composes these interfaces:

```
TELProcessor:
    anchor_verifier:    AnchorVerifier
    signature_verifier: SignatureVerifier
    identity_resolver:  IdentityResolver
    controller_auth:    ControllerAuthorizer
    storage:            (EventStore + SequenceIndex + StateStore + ...)

    process(event, anchor_proof, signatures) -> Result
```

An implementation targeting KERI would provide KERI-specific implementations
of each interface. An implementation targeting a blockchain would provide
blockchain-specific implementations. The TEL core logic remains the same.

---

## 14. Developer API

Builders hide field-level plumbing behind concept-level operations. The
developer expresses intent; the builder selects the correct event type,
constructs anchors, computes SAIDs, and enforces constraints.

### 14.1 Builders

#### RegistryBuilder

Creates a new registry. The mode (witnessless vs witnessed) is determined
by whether witnesses are configured.

```
RegistryBuilder
  .issuer(identifier)      -- the controller of this registry
  .witnesses(list)         -- witness identifiers (omit for witnessless)
  .threshold(n)            -- witness threshold (omit for witnessless)
  .no_witnesses()          -- shorthand: sets NB trait, empty witnesses, threshold 0
  .nonce(value)            -- cryptographic nonce (auto-generated if omitted)
  .build() → (vcp event, RegistryState)
```

**What it abstracts:**
- Selects `NB` trait automatically when `.no_witnesses()` is called
- Sets `bt = "0"`, `b = []` for witnessless mode
- Validates threshold against witness list size
- Generates nonce with sufficient entropy if not provided
- Computes SAID; sets `i = d` at inception

#### IssuanceBuilder

Issues a credential. The correct event type (`iss` or `bis`) is selected
automatically based on the registry mode.

```
IssuanceBuilder
  .credential(said)        -- SAID of the credential being issued
  .registry(state)         -- RegistryState (provides mode and current config)
  .datetime(dt)            -- issuance timestamp (optional)
  .build() → iss or bis event
```

**What it abstracts:**
- Selects `iss` (witnessless) or `bis` (witnessed) based on registry mode
- Constructs `ra` (registry anchor) automatically for witnessed mode
- Sets `s = "0"`, populates `ri` or `ii` from registry state

#### RevocationBuilder

Revokes a previously issued credential. Requires the issuance event for
digest chaining.

```
RevocationBuilder
  .credential(said)        -- SAID of the credential being revoked
  .registry(state)         -- RegistryState
  .issuance(event)         -- the prior issuance event (for digest chain)
  .datetime(dt)            -- revocation timestamp (optional)
  .build() → rev or brv event
```

**What it abstracts:**
- Selects `rev` (witnessless) or `brv` (witnessed) based on registry mode
- Constructs `ra` automatically for witnessed mode
- Sets `p` from issuance event's SAID, `s = "1"`

#### RegistryRotationBuilder

Modifies the witness roster of a witnessed registry.

```
RegistryRotationBuilder
  .registry(state)         -- current RegistryState
  .add(identifiers)        -- witnesses to add
  .remove(identifiers)     -- witnesses to remove (cut)
  .threshold(n)            -- new threshold (keeps current if omitted)
  .build() → vrt event
```

**What it abstracts:**
- Computes new witness list: `(current - cuts) ∪ adds`
- Validates no overlap between cuts and adds
- Validates cuts are subset of current witnesses, adds are not already present
- Sets `p` from current registry state's latest event SAID
- Sets `s = current_sn + 1`
- Rejects if registry has `NB` trait

### 14.2 Read-Only Views

#### RegistryState

```
RegistryState
  .identifier      -- registry identifier (SAID)
  .issuer          -- controller identifier
  .sequence        -- current sequence number
  .witnesses       -- current witness list
  .threshold       -- current witness threshold
  .no_witnesses    -- true if NB trait is set
  .latest_said     -- SAID of most recent registry event
  .traits          -- configuration trait list
```

Derived from registry state record (Section 10.1). Passed to builders to
provide registry context without exposing internal state records.

#### CredentialStatus

```
CredentialStatus
  .credential_id   -- credential SAID
  .registry_id     -- registry identifier
  .state           -- enum: NOT_ISSUED | ISSUED | REVOKED
  .issued_at       -- datetime of issuance (if issued)
  .revoked_at      -- datetime of revocation (if revoked)
```

Wraps the three-state answer from credential state record (Section 10.2).
This is the view that external consumers (e.g., ACDC verification) use.

### 14.3 Interface Boundaries

TEL exposes two interfaces to the broader KERI/ACDC ecosystem:

**`Primitives`** (consumed from [KEL Crypto](kel-crypto.md)): TEL uses SAID
computation and deterministic serialization from the crypto layer. Any
CESR-compliant primitives library satisfies this dependency.

**`CredentialStatus`** (exported to ACDC): The ACDC verification pipeline
queries TEL for credential status via the `CredentialStatus` view. The
[ACDC Verification](acdc-verification.md) spec depends on this interface —
it never imports TEL internals, it just asks "is this credential valid?"

### 14.4 Developer Persona Map

| Persona | Start With |
|---------|-----------|
| **Issuer dev** (creating registries, issuing/revoking) | §3-6, §14 (builders) |
| **Verifier dev** (checking credential status) | §6, §10-11, §14 (views) |
| **Infrastructure dev** (running TEL nodes, storage) | §9, §11-13 |
| **Integration dev** (plugging TEL into KERI/blockchain) | §13-14 (interfaces) |

---

## 15. Invariants

These properties MUST hold for any correct TEL implementation.

### 15.1 SAID Integrity

```
For every event E in the log:
    E.d == saidify(E).said
```

Every event is self-addressing. Modifying any field invalidates the SAID.

### 15.2 Digest Chain

```
For every non-inceptive event E at sn > 0:
    E.p == prior_event(E.i, E.s - 1).d
```

Every event chains to its predecessor by digest. The log is tamper-evident.

### 15.3 Sequential Ordering

```
For every event E:
    E.s == expected_next_sn(E.i)
```

No gaps, no duplicates, no reordering in the final log. Events may arrive
out of order but are only logged when the sequence is complete.

### 15.4 Registry Identifier Invariance

```
For all registry events R₀, R₁, ..., Rₙ in the same chain:
    R₀.i == R₁.i == ... == Rₙ.i
```

The registry identifier never changes.

### 15.5 Mode Consistency

```
If registry has NB trait:
    All credential events MUST be iss/rev (never bis/brv)
Else:
    All credential events MUST be bis/brv (never iss/rev)
```

The operating mode is fixed at inception.

### 15.6 Issuance Uniqueness

```
For any credential SAID C within a registry:
    At most ONE issuance event exists with i == C
```

A credential cannot be issued twice.

### 15.7 Revocation Requires Issuance

```
For any revocation event E:
    An issuance event exists with i == E.i and s == 0
```

You cannot revoke what was never issued.

### 15.8 Credential Finality

```
For any credential SAID C:
    At most TWO events exist: sn=0 (issuance) and sn=1 (revocation)
```

The credential lifecycle has exactly two possible states. There is no
"un-revoke" or "re-issue" operation.

### 15.9 Anchor Authorization

```
For every logged event E:
    anchor_verifier.verify(E, E.anchor_proof) == true
```

No event is logged without a valid anchor. Events without anchors are held
in escrow.

### 15.10 Witness Threshold

```
For every logged witnessed event E:
    count(valid_witness_signatures(E)) >= registry_state_at(E).threshold
```

No witnessed event is logged without meeting the signature threshold.

### 15.11 State Derivability

```
For any state record S:
    S == replay(all events for S.identifier from sn=0 to latest)
```

State records are always derivable from the log. The log is the source of
truth.

---

## 16. Security Considerations

### 16.1 Revocation Finality

Once a credential is revoked, it cannot be un-revoked. This is by design.
If an issuer needs to "reinstate" a credential, they issue a new credential
with a new SAID. This prevents confusion about historical state.

### 16.2 Eclipse Attacks

A verifier that cannot see the full TEL (e.g., due to network partition)
might believe a revoked credential is still valid. Mitigations:

- **Witnesses** provide redundant sources of truth.
- **Watchers** (external monitors) can independently verify TEL state.
- **Freshness requirements** — verifiers should require recent TEL state,
  not accept stale caches.

### 16.3 Witness Compromise

If an attacker compromises `threshold` witnesses, they can forge TEL events.
Mitigations:

- Use non-transferable (non-rotatable) identifiers for witnesses, reducing
  key management attack surface.
- Set threshold appropriately for the risk level.
- Monitor witnesses for equivocation (signing conflicting events).

### 16.4 Anchor Dependency

TEL's security is bounded by the security of its anchor mechanism. A
compromised anchor source (e.g., a key event log with compromised keys)
allows unauthorized TEL events. TEL inherits the security properties of
its trust anchor.

### 16.5 Replay Protection

Events are content-addressed (SAIDed) and sequence-numbered. Replaying an
already-logged event is idempotent — the event is recognized as a duplicate
and silently ignored. Replaying an event with the same sequence number but
different content produces a different SAID, which is detected as
duplicitous.

### 16.6 Timing Attacks

The `dt` (datetime) field is self-reported by the event creator and is NOT
cryptographically verified. An issuer can backdate or future-date events.
For authoritative timestamps, use the anchor event's timestamp (which is
bound to the trust source's timing guarantees).

### 16.7 Proof of State

A verifier with the controlling KEL and TEL can cryptographically verify registry state without trusting any intermediary. This is TEL's core security property: trustless state verification. The combination of anchor binding (proving authorization), digest chaining (proving integrity), and witness signatures (proving attestation) means that any party with access to the event logs can independently derive and verify the current state of any credential.

### 16.8 Registry Nonce Entropy

The registry inception nonce (`n`) MUST have sufficient entropy (minimum
128 bits). A predictable nonce allows an attacker to pre-compute registry
identifiers and potentially pre-position conflicting events.

---

## 17. Reference Examples

### 17.1 Witnessless Registry Lifecycle

**Step 1: Create registry**

```json
{
    "v": "KERI10JSON0000ab.",
    "t": "vcp",
    "d": "<SAID of this event>",
    "i": "<equals d — registry identifier>",
    "ii": "DFghJK...",
    "s": "0",
    "c": ["NB"],
    "bt": "0",
    "b": [],
    "n": "AHjq7kRb..."
}
```

**Step 2: Issue a credential**

```json
{
    "v": "KERI10JSON00008a.",
    "t": "iss",
    "d": "<SAID of this event>",
    "i": "EMRvS7lG...",
    "s": "0",
    "ri": "<registry identifier from step 1>",
    "dt": "2026-03-04T12:00:00.000000+00:00"
}
```

**Step 3: Revoke the credential**

```json
{
    "v": "KERI10JSON00009c.",
    "t": "rev",
    "d": "<SAID of this event>",
    "i": "EMRvS7lG...",
    "s": "1",
    "ri": "<registry identifier>",
    "p": "<SAID from step 2>",
    "dt": "2026-03-04T18:30:00.000000+00:00"
}
```

### 17.2 Witnessed Registry Lifecycle

**Step 1: Create registry with 2 witnesses, threshold 2**

```json
{
    "v": "KERI10JSON0000cd.",
    "t": "vcp",
    "d": "<SAID>",
    "i": "<equals d>",
    "ii": "DFghJK...",
    "s": "0",
    "c": [],
    "bt": "2",
    "b": ["BBilc4...", "BFrOe1..."],
    "n": "AKxy9mR..."
}
```

**Step 2: Issue with registry anchor**

```json
{
    "v": "KERI10JSON0000bc.",
    "t": "bis",
    "d": "<SAID>",
    "i": "EJymtAC...",
    "ii": "<registry identifier>",
    "s": "0",
    "ra": {
        "i": "<registry identifier>",
        "s": "0",
        "d": "<SAID of vcp event>"
    },
    "dt": "2026-03-04T12:00:00.000000+00:00"
}
```

Both witnesses must co-sign this event (threshold = 2).

### 17.3 Registry Rotation

```json
{
    "v": "KERI10JSON0000ab.",
    "t": "vrt",
    "d": "<SAID>",
    "i": "<registry identifier>",
    "p": "<SAID of prior vcp or vrt>",
    "s": "1",
    "bt": "2",
    "br": ["BBilc4..."],
    "ba": ["BCdef5..."]
}
```

Removes one witness, adds another. Threshold stays at 2. Future credential
events must be co-signed by the new witness roster.

---

## Appendix A: Event Type Summary

| Code | Name | Mode | Chain | SN | Prior | Anchor | Witnesses |
|------|------|------|-------|----|-------|--------|---------|
| `vcp` | Registry Inception | Both | Registry | 0 | -- | Optional | Config only |
| `vrt` | Registry Rotation | Witnessed only | Registry | 1+ | Required | Required | Modifies roster |
| `iss` | Simple Issuance | Witnessless | Credential | 0 | -- | Required | Not used |
| `rev` | Simple Revocation | Witnessless | Credential | 1 | Required | Required | Not used |
| `bis` | Witnessed Issuance | Witnessed | Credential | 0 | -- | Required | Required |
| `brv` | Witnessed Revocation | Witnessed | Credential | 1 | Required | Required | Required |

## Appendix B: Configuration Traits

| Trait | Code | Effect |
|-------|------|--------|
| No (dedicated) Witnesses | `NB` | Registry operates without dedicated witnesses. Only `iss`/`rev` events allowed. No rotation. |
| Establishment Only | `EO` | Registry accepts only registry events (`vcp`/`vrt`). No credential events. Use case: a root registry that governs other registries but does not directly issue credentials. |

## Appendix C: Field Type Definitions

| Type | Format | Example |
|------|--------|---------|
| VersionString | `PPPPMmmGggKKKKSSSSS.` (20 chars) | `"KERI10JSON0000ab."` |
| SAID | Qualified Base64url digest (44 or 88 chars) | `"EJymtAC4piy_HkHWRs4J..."` |
| Identifier | Qualified Base64url public key or digest | `"DFghJKlm..."` |
| HexString | Lowercase hexadecimal, no leading zeros (except `"0"`) | `"0"`, `"1"`, `"a"`, `"1f"` |
| Nonce | Qualified Base64url random bytes | `"AHjq7kRbWg..."` |
| DateTimeString | ISO 8601 with microsecond precision | `"2026-03-04T12:00:00.000000+00:00"` |
| AnchorMap | `{"i": Identifier, "s": HexString, "d": SAID}` | See Section 5.3 |

## Appendix D: Concept Dependency Matrix

| Concept | SAID | Serialization | Storage | Anchor Verifier | Sig Verifier | Identity Resolver |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| **Event creation** | X | X | -- | -- | -- | -- |
| **Event logging** | X | X | X | -- | -- | -- |
| **Anchor verification** | -- | -- | -- | X | -- | -- |
| **Witness verification** | -- | -- | -- | -- | X | X |
| **State query** | -- | -- | X | -- | -- | -- |
| **Registry rotation** | X | X | X | X | -- | -- |
| **Escrow processing** | -- | -- | X | X | X | X |

Note: **Event creation** needs only SAID and serialization — no external
dependencies. This is the most isolatable operation and can be implemented
as a standalone library.
