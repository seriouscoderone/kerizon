# Registrar Core Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification of the KERI Registrar role — the
infrastructure component that orchestrates TEL registry operations on behalf of
a controlling identifier. The Registrar manages the lifecycle of registry events
(inception, issuance, revocation, rotation) including witness receipting and
multisig coordination, abstracting the operational complexity of TEL management.
**Normative basis:** KERI Specification, TEL Specification, CESR Specification
**Cross-checked against:** keripy reference implementation (`credentialing.py`,
`viring.py`, `kering.py`, `counting.py`, `grouping.py`, `agenting.py`)

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Terminology](#2-terminology)
3. [Component Hierarchy](#3-component-hierarchy)
4. [Registrar Role and Responsibilities](#4-registrar-role-and-responsibilities)
5. [Registry Lifecycle Operations](#5-registry-lifecycle-operations)
6. [Anchor Binding](#6-anchor-binding)
7. [Escrow Pipeline](#7-escrow-pipeline)
8. [Multisig Registry Operations](#8-multisig-registry-operations)
9. [Completion Semantics](#9-completion-semantics)
10. [Endpoint Role](#10-endpoint-role)
11. [CESR Attachment Codes](#11-cesr-attachment-codes)
12. [Security Considerations](#12-security-considerations)
13. [Implementation Notes](#13-implementation-notes)

---

## 1. Purpose and Scope

A TEL Registry (specified in the [TEL Specification](tel-specification.md)) is a
pair of event logs — a Management TEL for registry state and per-credential VC
TELs for issuance/revocation tracking. The Registry is the *data structure*. The
Registrar is the *operator* — the infrastructure component that creates,
anchors, witnesses, and disseminates registry events.

This distinction matters because:

- **Registry** defines *what* the TEL contains (event types, fields, state
  transitions)
- **Registrar** defines *how* TEL events are orchestrated (anchoring to KEL,
  collecting witness receipts, coordinating multisig participants, disseminating
  to witnesses)

The Registrar sits at the same infrastructure layer as Witnesses, Watchers, and
Mailboxes — it is a service that operates on behalf of a controlling identifier
rather than a data structure within the protocol.

This specification covers:

- The Registrar's role in the KERI infrastructure stack
- How registry operations (inception, issuance, revocation, rotation) are
  orchestrated
- The anchor binding between TEL events and KEL events
- The three-stage escrow pipeline for TEL event completion
- Multisig coordination for group-controlled registries
- Completion semantics for determining when a TEL event is finalized

This specification does **not** cover:

- **TEL event structure**: defined in the [TEL Specification](tel-specification.md)
- **Credential construction**: creating ACDC content is the Credentialer's
  concern, not the Registrar's
- **Schema validation**: verifying credentials against schemas is orthogonal
- **Exchange protocol**: how credentials are presented (IPEX) is a separate
  concern

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Registrar** | Infrastructure component that orchestrates TEL registry operations (inception, issuance, revocation) on behalf of a controlling identifier |
| **Registry** | A TEL instance: one Management TEL plus zero or more per-credential VC TELs |
| **Management TEL** | The registry-level event chain (events: `vcp`, `vrt`) that governs witness configuration |
| **VC TEL** | A per-credential event chain (events: `iss`/`rev` or `bis`/`brv`) tracking issuance and revocation |
| **Regery** | Registry environment manager — creates, loads, and provides access to registries and their TEL event processor (Tevery) |
| **Reger** | TEL database — stores TEL events, state, and escrow data |
| **Tevery** | TEL event processor — validates and applies TEL events to state (analogous to Kevery for KEL) |
| **Anchor** | A cryptographic binding of a TEL event SAID to a specific KEL event (sequence number + digest) |
| **Counselor** | Multisig coordination component that manages partially-signed group events through to completion |
| **Credentialer** | Higher-level component that creates credentials, delegates TEL operations to the Registrar, and manages credential escrow |

---

## 3. Component Hierarchy

The Registrar operates within a layered component stack:

```
    ┌──────────────────────────┐
    │      Credentialer        │  credential creation, validation,
    │  (uses Registrar)        │  schema checking
    └────────────┬─────────────┘
                 │ delegates TEL operations
    ┌────────────▼─────────────┐
    │       Registrar          │  orchestration: anchor, witness,
    │  (uses Regery, Counselor)│  multisig, disseminate
    └──┬─────────┬─────────┬───┘
       │         │         │
  ┌────▼───┐ ┌──▼────┐ ┌──▼──────────┐
  │ Regery │ │Counsel│ │ Receiptor   │
  │        │ │  or   │ │ WitPublisher│
  └───┬────┘ └───────┘ └─────────────┘
      │
  ┌───▼────┐
  │Registry│  TEL data structure
  │(+ Reger│  (Management TEL + VC TELs)
  │+ Tevery│
  └────────┘
```

**Data flow:**

1. **Credentialer** creates the credential (ACDC) and calls **Registrar** for
   TEL operations
2. **Registrar** delegates to **Registry** for TEL event construction, then
   handles anchoring, witness receipting, and multisig coordination
3. **Registry** constructs TEL events and processes them through **Tevery**
4. **Reger** persists TEL events and escrow state

---

## 4. Registrar Role and Responsibilities

The Registrar is a long-running process (DoDoer) with three concurrent doers:

| Doer | Purpose |
|------|---------|
| **Receiptor** | Collects witness receipts for the KEL anchoring event |
| **WitnessPublisher** | Disseminates completed TEL events to witnesses |
| **escrowDo** | Processes the three escrow stages on a periodic tick |

The Registrar handles four operations:

| Operation | TEL Event | KEL Anchor |
|-----------|-----------|-----------|
| **Registry inception** | `vcp` (Management TEL inception) | Interaction event (`ixn`) with registry seal |
| **Credential issuance** | `iss` or `bis` (VC TEL inception) | Interaction event with issuance seal |
| **Credential revocation** | `rev` or `brv` (VC TEL event) | Interaction event with revocation seal |
| **Registry rotation** | `vrt` (Management TEL rotation) | Interaction event with rotation seal |

Each operation follows the same pattern:

1. Construct the TEL event (via Registry)
2. Create a KEL anchoring event containing a seal to the TEL event
3. Enter the appropriate escrow based on single-sig vs multisig
4. Process through the escrow pipeline to completion

---

## 5. Registry Lifecycle Operations

### 5.1 Registry Inception

Creates a new registry with a Management TEL inception event (`vcp`).

**Inputs:**
- TEL inception serder (`iserder`) containing registry configuration
- KEL anchoring event serder (`anc`)

**Configuration options** (set at inception, immutable afterward):
- `noBackers` (trait `NB`): registry does not use dedicated TEL witnesses
- `estOnly` (trait `EO`): registry requires rotation events for all state
  changes — no interaction events
- `baks`: initial list of TEL witness prefixes (when not `NB`)
- `toad`: TEL witness threshold
- `nonce`: random seed for registry identifier derivation

**Processing (single-sig):**
1. Anchor the TEL event: bind `vcp` SAID to the current KEL event (sequence
   number + digest)
2. Request witness receipts for the anchoring KEL event
3. Enter witness escrow (`tpwe`)

**Processing (multisig):**
1. Start Counselor coordination for the anchoring KEL event
2. Enter multisig escrow (`tmse`)

### 5.2 Credential Issuance

Creates a VC TEL inception event for a specific credential.

**Inputs:**
- Credential serder (`creder`) identifying the registry via `ri` (registry
  identifier)
- TEL issuance serder (`iserder`) — either `iss` (witnessless) or `bis`
  (witnessed)
- KEL anchoring event serder (`anc`)

**TEL event selection:**
- If `noBackers`: generates `iss` event (simple issuance, no witness sigs)
- If witnessed: generates `bis` event (backer issuance, includes registry
  anchor `ra` seal)

**Processing:** Same anchor → escrow pattern as inception.

### 5.3 Credential Revocation

Creates a VC TEL revocation event for a previously issued credential.

**Inputs:**
- Credential serder (`creder`)
- TEL revocation serder (`rserder`) — either `rev` or `brv`
- KEL anchoring event serder (`anc`)

**Precondition:** The credential MUST have been previously issued (VC TEL
sequence 0 must exist in the database).

**TEL event selection:**
- If `noBackers`: generates `rev` event
- If witnessed: generates `brv` event

**Processing:** Same anchor → escrow pattern as inception and issuance.

### 5.4 Registry Rotation

Rotates the witness list for a witnessed registry.

**Precondition:** The registry MUST support witnesses (`noBackers` is false).

**Inputs:**
- `toad`: new witness threshold
- `cuts`: list of witness prefixes to remove
- `adds`: list of witness prefixes to add

**Produces:** A `vrt` event on the Management TEL.

---

## 6. Anchor Binding

Every TEL event MUST be anchored to a KEL event. This binding is what gives TEL
events their cryptographic authority — the TEL event's validity is derived from
the controlling identifier's key state at the time of the anchoring KEL event.

**Anchor structure:**

```
TEL event (vcp/iss/rev/bis/brv/vrt)
    │
    │ SAID
    ▼
KEL interaction event (ixn)
    data: [{seal referencing TEL event SAID}]
    │
    │ signed by controlling keys
    ▼
Witness receipts on KEL event
```

**Anchor database entry:**

| Key | Value |
|-----|-------|
| `dgKey(pre, regd)` | `(sequence_number, digest)` |

Where:
- `pre`: TEL event identifier (`i` field) — registry prefix for `vcp`/`vrt`,
  credential SAID for `iss`/`rev`/`bis`/`brv`
- `regd`: TEL event SAID (`d` field)
- `sequence_number`: KEL event sequence number of the anchoring `ixn`
- `digest`: KEL event SAID of the anchoring `ixn`

This binding allows validators to verify: "this TEL event was authorized by key
state X at KEL sequence number N."

---

## 7. Escrow Pipeline

TEL events pass through a three-stage escrow pipeline. Each stage gate must be
satisfied before advancing to the next.

```
  ┌─────────────────────────────────┐
  │        TEL Event Created        │
  └──────────────┬──────────────────┘
                 │
         ┌───────▼────────┐
         │ Single-sig?    │
         └──┬──────────┬──┘
          yes          no
            │           │
  ┌─────────▼──┐  ┌────▼──────────┐
  │   tpwe     │  │    tmse       │
  │  Witness   │  │  Multisig     │
  │  Escrow    │  │  Escrow       │
  └─────┬──────┘  └──────┬────────┘
        │                │
        │    ┌───────────┘
        │    │
        ▼    ▼
  ┌──────────────┐
  │    tede      │
  │ Dissemination│
  │   Escrow     │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │    ctel      │
  │  Completed   │
  └──────────────┘
```

### 7.1 Witness Escrow (`tpwe`)

**Full name:** TEL Partial Witness Escrow

**Entry condition:** Single-sig registry event where the KEL anchoring event
needs witness receipts.

**Key:** `(registry_or_credential_id, tel_sequence_number)`

**Value:** `(Prefixer, Number, Diger)` — the controlling identifier's prefix,
the KEL anchoring event's sequence number, and its digest.

**Exit condition:** ALL witness receipts collected for the KEL anchoring event.
Specifically:
- Load all witness signatures (`wigs`) for the anchoring event
- Compare count against the identifier's witness list length
- Verify the Receiptor has confirmed witnessing is complete

**On exit:** Remove from `tpwe`, add to `tede` (dissemination escrow).

**Special case:** If the identifier has no witnesses (`kever.wits` is empty),
the event passes through `tpwe` immediately.

### 7.2 Multisig Escrow (`tmse`)

**Full name:** TEL Multisig Escrow

**Entry condition:** Group multisig registry event where the KEL anchoring event
requires signatures from multiple participants.

**Key:** `(registry_or_credential_id, tel_sequence_number, tel_event_said)`

**Value:** `(Prefixer, Number, Diger)` — same as `tpwe`.

**Processing:** The Counselor handles the multisig coordination:
1. Send local signature to other group participants
2. Wait for signature threshold to be met
3. If delegated identifier: handle delegation anchor
4. If elected leader: send event to witnesses and collect receipts
5. Otherwise: wait for fully receipted event

**Exit condition:** `counselor.complete()` returns true — all required
signatures have been collected and the KEL event is finalized.

**On exit:** Anchor the TEL event (write anchor database entry), remove from
`tmse`, add to `tede`.

**Error handling:** If `counselor.complete()` raises `ValidationError`, the
entry is removed from escrow (the multisig coordination has irrecoverably
failed).

### 7.3 Dissemination Escrow (`tede`)

**Full name:** TEL Event Dissemination Escrow

**Entry condition:** A TEL event whose KEL anchoring event is fully signed and
(if applicable) fully witnessed.

**Key:** `(registry_or_credential_id, tel_sequence_number)`

**Value:** `(Prefixer, Number, Saider)`

**Exit condition:** The TEL event exists in the TEL database (`tels` sub-db).
This confirms the Tevery has successfully processed and stored the event.

**Processing on exit:**
1. Clone the TEL event stream from the registry prefix at the relevant
   sequence number
2. Send the cloned TEL event bytes to WitnessPublisher for fire-and-forget
   dissemination to witnesses
3. Record completion in `ctel`

### 7.4 Completion Record (`ctel`)

**Full name:** Completed TEL Event

**Key:** `(registry_or_credential_id, tel_sequence_number)`

**Value:** `Saider` — the SAID of the completed TEL event.

This is the terminal state. Once recorded in `ctel`, the TEL event is
considered fully processed and disseminated.

---

## 8. Multisig Registry Operations

When the controlling identifier is a group multisig (GroupHab), all TEL
operations require coordination through the Counselor.

### 8.1 Interaction Event Creation

For multisig registries, the Registrar creates a KEL interaction event (`ixn`)
containing a registry seal, then initiates Counselor coordination:

```
ixn = hab.interact(data=[registry_seal])

counselor.start(
    prefixer = group_prefix,
    number   = ixn_sequence_number,
    diger    = ixn_said
)
```

The Counselor manages:
- Distributing the partial event to other group members via EXN
- Collecting signatures from participants
- Handling delegation anchoring if the group is delegated
- Collecting witness receipts once all signatures are gathered

### 8.2 Flow Difference from Single-Sig

| Step | Single-Sig | Multisig |
|------|-----------|----------|
| 1. Construct TEL event | Registry.make/issue/revoke | Same |
| 2. Create KEL anchor | hab.interact → direct | hab.interact → Counselor.start |
| 3. Anchor TEL to KEL | Immediate (anchorMsg) | Deferred (after Counselor completes) |
| 4. Collect signatures | N/A (single signer) | Counselor escrow |
| 5. Witness receipts | Receiptor (tpwe) | Counselor handles |
| 6. Disseminate | tede → WitnessPublisher | tede → WitnessPublisher |

The key difference: for single-sig, the anchor is written immediately and the
event enters `tpwe` for witness receipting. For multisig, the anchor is
*deferred* until the Counselor confirms all signatures are collected, and the
event enters `tmse` instead.

---

## 9. Completion Semantics

A TEL event is considered **complete** when two conditions are met:

1. **TEL event is committed:** The `ctel` database contains a SAID entry for
   the given `(prefix, sequence_number)` pair
2. **Witnesses have been notified:** The WitnessPublisher has processed the
   dissemination message for this event

```
complete(pre, sn) =
    ctel.get(pre, sn) is not None
    AND witPub.sent(said=pre)
```

The Credentialer uses `registrar.complete()` to determine when it is safe to
proceed with credential-level operations (e.g., marking a credential as fully
issued in the credential completion database `ccrd`).

> **Note:** Completion is a local property. It means the local node has fully
> processed the TEL event and disseminated it to witnesses. It does NOT mean
> all witnesses have acknowledged receipt — dissemination is fire-and-forget.
> Consumers must query witnesses directly to confirm they have received the TEL
> events.

---

## 10. Endpoint Role

The Registrar is a defined KERI endpoint role, allowing controllers to authorize
Registrar service endpoints via OOBI and BADA:

```
Roles.registrar = 'registrar'
```

This places the Registrar alongside other infrastructure roles:

| Role | Infrastructure Function |
|------|------------------------|
| `witness` | Receipt and store KEL events |
| `watcher` | Monitor and detect duplicity |
| `mailbox` | Queue and forward messages |
| `registrar` | Operate TEL registries |
| `agent` | Cloud agent (Signify) |

A controller authorizes a Registrar endpoint via the standard OKEA mechanism
(`/end/role/add` reply message), allowing verifiers to discover where a
controller's registry is hosted.

---

## 11. CESR Attachment Codes

TEL events use specific CESR counter codes for seal attachments:

| Counter Code | Name | Structure | Purpose |
|-------------|------|-----------|---------|
| `-V` | BackerRegistrarSealCouples | `(brid, dig)` | Seal coupling a backer/registrar identifier with the digest of sealed data |
| `--V` | BigBackerRegistrarSealCouples | `(brid, dig)` | Large version of the above |

The `SealBack` named tuple carries the registrar seal data:
- `bi`: backer/registrar identifier prefix
- `d`: digest of the sealed data

These seals allow TEL events to reference their authorizing registrar within
CESR-native attachment frames.

---

## 12. Security Considerations

### 12.1 Authority Derivation

The Registrar has no independent authority. All TEL event authorization derives
from the controlling identifier's key state:

- TEL events are anchored to KEL events signed by the controller's current keys
- Witness receipts are collected on the KEL anchoring event, not the TEL event
  directly
- A compromised Registrar without access to signing keys cannot forge TEL events

### 12.2 Escrow Integrity

Each escrow stage acts as a gate:

- **tpwe** ensures witness receipting is complete before dissemination
- **tmse** ensures all multisig participants have signed before anchoring
- **tede** ensures the Tevery has processed the event before disseminating

Events cannot skip escrow stages. A TEL event that enters `tpwe` must
pass through `tede` before reaching `ctel`.

### 12.3 Fire-and-Forget Dissemination

TEL event dissemination to witnesses is fire-and-forget. This means:

- The Registrar does not retry failed witness deliveries
- Consumers (verifiers, holders) must query witnesses to confirm receipt
- The `complete()` check indicates local processing completion, not global
  confirmation

This is a deliberate design choice: the Registrar's job is to ensure the
event is properly constructed, signed, and anchored. Delivery guarantees are
the transport layer's concern.

### 12.4 Multisig Failure Modes

If the Counselor encounters a `ValidationError` during multisig processing:

- The `tmse` entry is removed (escrow cleanup)
- The TEL event is NOT anchored
- The credential operation fails

This prevents partially-signed TEL events from being anchored and disseminated.

---

## 13. Implementation Notes

### 13.1 Escrow Processing Cadence

The escrow processor runs on a periodic tick (default: 0.5 seconds). Each tick
processes all three escrow stages in order:

```
processEscrows():
    processWitnessEscrow()     # tpwe → tede
    processMultisigEscrow()    # tmse → tede
    processDisseminationEscrow()  # tede → ctel
```

### 13.2 Registry Configuration Traits

Registry configuration is set at inception via the TEL `c` (configuration)
field:

| Trait Code | Name | Effect |
|-----------|------|--------|
| `NB` | NoBackers | Registry does not use dedicated TEL witnesses. TEL events rely solely on KEL witness receipts. |
| `EO` | EstOnly | Registry requires establishment events (rotation) for all state changes. No interaction events. |
| `RB` | RegistrarBackers | Registrar-provided backers are specified in a registrar seal in the event. |
| `NRB` | NoRegistrarBackers | Do not allow registrar-provided backers. |

> **Note:** `NB` is the most common configuration. Most registries operate
> without dedicated TEL witnesses, relying instead on the controlling
> identifier's KEL witnesses for availability.

### 13.3 Regery Initialization

The Regery performs lazy loading of existing registries from the database on
startup. For each stored `RegistryRecord`, it reconstructs a `Registry` object
bound to the correct `Hab`, `Reger`, `Tevery`, and `Parser` instances.

### 13.4 Relationship to Credentialer

The Credentialer sits above the Registrar in the component stack:

1. **Credentialer** creates the credential (ACDC) and validates it against its
   schema
2. **Credentialer** calls `registrar.issue()` to handle the TEL operation
3. **Credentialer** polls `registrar.complete()` to know when TEL processing
   finishes
4. **Credentialer** records the credential in `ccrd` (completed credentials)

The Registrar never touches credential content — it only orchestrates the TEL
events that track credential lifecycle state.
