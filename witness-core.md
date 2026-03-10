# Witness Core Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification of the KERI Witness role — what
witnesses are, how they are designated, what they do, and the first-seen policy
that is central to their function.
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Terminology](#2-terminology)
3. [Witness Role and Designation](#3-witness-role-and-designation)
4. [First-Seen Policy](#4-first-seen-policy)
5. [Receipt Creation and Validation](#5-receipt-creation-and-validation)
6. [Witness List Management](#6-witness-list-management)
7. [TOAD (Threshold of Accountable Duplicity)](#7-toad-threshold-of-accountable-duplicity)
8. [Witness AID Requirements](#8-witness-aid-requirements)
9. [Witness-Controller Interaction Model](#9-witness-controller-interaction-model)
10. [Security Considerations](#10-security-considerations)
11. [Implementation Notes](#11-implementation-notes)

---

## 1. Purpose and Scope

A witness is a controller-designated entity that receives, verifies, receipts
(signs), and stores key events on behalf of an identifier. Witnesses provide
the availability and accountability infrastructure for KERI identifiers.

This specification covers:

- The witness role: what a witness does and what it does not do
- How witnesses are designated and managed in establishment events
- The first-seen policy that governs witness behavior
- How receipts are created, attached, and validated
- The TOAD mechanism for accountable duplicity detection

This specification does **not** cover:

- **KAWA** (KERI Agreement Algorithm for Watchers): the BFT agreement protocol
  among witnesses is specified separately
- **Watcher** behavior: watchers are validator infrastructure, not controller
  infrastructure
- **Key event structure**: defined in the KEL Core specification
- **Network transport**: witnesses may be reached via HTTP, TCP, or any
  transport protocol

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Witness** | A controller-designated entity committed in establishment events that receives, verifies, receipts, and stores key events for a specific identifier. Witnesses are controller infrastructure, not validator infrastructure. |
| **KERL** | Key Event Receipt Log. A KEL that also includes all consistent key event receipt messages from the witness set. A KERL is the witness's complete view of an identifier's history. |
| **TOAD** | Threshold of Accountable Duplicity. The minimum number of witness receipts a validator requires before accepting an event as established. Encoded in the `bt` field. |
| **Receipt** | A signed acknowledgment of a key event by a witness (or other entity). A receipt event has ilk `rct` and references the receipted event by AID prefix, sequence number, and SAID. |
| **First-Seen** | The policy by which a witness only accepts and receipts the FIRST valid version of an event it encounters at a given sequence number. Once first-seen, a version is "always seen, never unseen." |
| **Backer** | Synonym for witness in field labels. The `b` field contains backer (witness) AID prefixes. |
| **Non-transferable AID** | An identifier that cannot rotate keys. Uses a non-transferable prefix code (e.g., `B` for Ed25519) and has an empty next-key digest list. Recommended for witnesses. |

---

## 3. Witness Role and Designation

### 3.1 What a Witness Does

A witness performs four essential functions:

1. **Receives** key events submitted by the controller
2. **Verifies** the event's controller signatures against the identifier's
   current key state
3. **Receipts** the event by signing the event's serialized bytes and returning
   a receipt message
4. **Stores** the event and receipt in its local KERL

A witness also:

- Serves its stored events and receipts to validators, watchers, and other
  witnesses upon request
- Propagates receipts from other witnesses (cross-receipt dissemination)
- Enforces the first-seen policy (Section 4)

### 3.2 What a Witness Does NOT Do

- A witness does **not** control or hold private signing keys for the
  identifier it witnesses
- A witness does **not** decide event ordering — the controller determines
  sequence numbers
- A witness does **not** perform consensus with other witnesses autonomously
  (that is KAWA's role)
- A witness is **not** a validator — it serves the controller, not the verifier

### 3.3 Designation in Establishment Events

Witnesses are committed to an identifier through the `b` (backers) field in
establishment events. The initial witness set is declared at inception; it may
be modified at rotation.

**Inception event (`icp` / `dip`):**

| Field | Purpose |
|-------|---------|
| `b`   | Ordered list of witness AID prefixes (qb64 strings) |
| `bt`  | Witness threshold (TOAD) as hex string |

**Rotation event (`rot` / `drt`):**

| Field | Purpose |
|-------|---------|
| `ba`  | List of witness AID prefixes to add |
| `br`  | List of witness AID prefixes to remove |
| `bt`  | Updated witness threshold (TOAD) as hex string |

The `b` field in an inception event establishes the initial ordered witness
list. Rotation events use differential updates via `br` (removes) and `ba`
(adds) — the full witness list is derived algorithmically (see Section 6).

### 3.4 Witness Set as a Commitment

The witness list in an establishment event is a cryptographic commitment.
Because the event's SAID is computed over its entire serialization (including
the `b`, `br`, `ba`, and `bt` fields), any modification to the witness
configuration would invalidate the event's digest chain. This means:

- The controller cannot retroactively change which witnesses are designated
- Validators can independently verify the witness set for any point in the KEL
- Witness additions and removals are recorded in the tamper-evident log

---

## 4. First-Seen Policy

### 4.1 Core Principle

The first-seen policy is the foundational rule governing witness behavior:

> **First seen, always seen, never unseen.**

When a witness receives a valid event at a given sequence number for a given
identifier, it records that event as "first seen" and will never accept a
different event at the same sequence number for the same identifier. The
first-seen event becomes the only version the witness will receipt and serve.

### 4.2 First-Seen Ordering

Each witness maintains a monotonically increasing first-seen ordinal number
(`fn`) for events it processes. The first-seen ordinal provides a total
ordering of all events across all identifiers as observed by that witness.

```
First-seen log (per witness):
  fn=0  →  AID_A icp (sn=0)
  fn=1  →  AID_B icp (sn=0)
  fn=2  →  AID_A ixn (sn=1)
  fn=3  →  AID_B rot (sn=1)
  ...
```

The first-seen ordinal is witness-local: different witnesses may assign
different `fn` values to the same event. The `fn` establishes causal ordering
within a single witness's observation history.

### 4.3 First-Seen Timestamp

In addition to the ordinal, the witness records a first-seen datetime (`dts`)
as an ISO-8601 timestamp. This provides a human-readable temporal reference but
is not used for ordering decisions — the ordinal is authoritative.

### 4.4 Implications

The first-seen policy has several critical implications:

1. **Duplicity detection:** If a controller sends two different events at the
   same sequence number to different witnesses, some witnesses will have
   first-seen one version and some the other. This disagreement among witnesses
   is detectable and constitutes provable duplicity.

2. **Immutability:** Once a witness has receipted an event, it cannot be asked
   to "un-receipt" it or replace it with a different version. The witness's
   KERL is append-only and version-final per sequence number.

3. **No retroactive changes:** A controller cannot convince a witness to
   replace a previously seen event with a new one, even if the new event has
   valid signatures.

### 4.5 Handling Duplicate Submissions

When a witness receives an event at a sequence number it has already recorded:

- **Same SAID as first-seen:** The event is a duplicate of the already-accepted
  version. The witness may return the existing receipt. This is idempotent.
- **Different SAID from first-seen:** The event conflicts with the first-seen
  version. The witness MUST reject this event. This constitutes evidence of
  attempted duplicity by the controller.

---

## 5. Receipt Creation and Validation

### 5.1 Receipt Event Structure

A receipt is a key event with ilk `rct`. It references the receipted event but
does not carry its own SAID computation — the `d` field contains the receipted
event's SAID.

```
Receipt event fields (ordered): v, t, d, i, s

  v  — Version string
  t  — "rct" (receipt ilk)
  d  — SAID of the receipted event (NOT a self-computed digest)
  i  — AID prefix of the receipted event
  s  — Sequence number of the receipted event (hex string)
```

The receipt body identifies WHICH event is being receipted. The actual
signature proving WHO receipted it is carried as an attachment to the receipt
message, not in the event body.

### 5.2 Non-Transferable Witness Receipts

When a witness has a non-transferable AID (recommended), it produces
**witness indexed signatures** (`wigers`). These are indexed signatures where
the index corresponds to the witness's position in the current witness list.

```
Receipt creation (non-transferable witness):

  1. Verify own AID appears in kever.wits for the receipted event's AID
  2. Determine index = position of own AID in kever.wits
  3. Sign the receipted event's serialized bytes using own signing key
  4. Create a Siger with the signature bytes and the witness index
  5. Construct receipt message:
     a. Receipt event body (rct serder)
     b. Witness indexed signature count code
     c. Witness indexed signature(s)
  6. Process the receipt into own local database
  7. Return the receipt message
```

The witness index is critical: it allows a validator to look up which witness
produced the signature by consulting the witness list from the appropriate
establishment event.

### 5.3 Transferable Receipts

Transferable AID receipts use a different attachment format: a seal referencing
the receipter's own establishment event plus indexed controller signatures
(`sigers`). This format is used when the receipter is a transferable AID (not
typical for witnesses, but supported for validators and endorsers).

```
Transferable receipt attachment:
  1. Event seal: { i: receipter_pre, s: receipter_last_est_sn, d: receipter_last_est_said }
  2. Indexed signatures from the receipter's current signing keys
```

### 5.4 Receipt Couple Format

Non-transferable non-witness receipts (e.g., from watchers) use receipt
couples: a `(verfer, cigar)` pair where `verfer` is the receipter's public key
and `cigar` is the unindexed signature.

### 5.5 Receipt Validation (processReceipt)

When a Kevery processes an incoming receipt:

```
processReceipt(serder, cigars, wigers, tsgs):

  1. Extract pre, sn, said from the receipt serder
  2. Look up the last-seen event digest at sn for pre
  3. If no event exists at that sn:
     → Escrow the receipt for later processing
     → Raise UnverifiedReceiptError
  4. If event exists but receipt's said does not match:
     → Stale receipt — discard
     → Raise ValidationError("Stale receipt")
  5. For each cigar (non-transferable receipt couple):
     a. Skip transferable verfers
     b. Skip own receipts of own events (unless local)
     c. Verify signature against the receipted event bytes
     d. If verfer is in the witness list → promote to indexed wiger, store in wigs db
     e. If verfer is NOT a witness → store in rcts db as endorser receipt
  6. For each wiger (witness indexed signature):
     a. Look up witness verfer from witness list at the appropriate index
     b. Skip transferable witness verfers
     c. Skip own witness receipts (unless local)
     d. Verify signature against the receipted event bytes
     e. Store in wigs db
  7. For each tsg (transferable signature group):
     a. Look up receipter's establishment event
     b. If not found → escrow as unverified transferable receipt
     c. Verify signatures against receipter's keys
     d. Store in vrcs db
```

### 5.6 Witness State Lookup

To validate witness receipts, the system must determine which witnesses were
active at the time of the receipted event. The `fetchWitnessState(pre, sn)`
function resolves this:

```
fetchWitnessState(pre, sn):
  1. Walk backwards through the KEL from sn
  2. Find the most recent establishment event at or before sn
  3. Return the witness list from that establishment event
```

This is necessary because interaction events do not change the witness list —
only establishment events do. A receipt for an interaction event at sn=5 must
be validated against the witness list from the most recent establishment event
at or before sn=5.

---

## 6. Witness List Management

### 6.1 Initial Witness Set (Inception)

The `b` field in an inception event contains the ordered list of witness AID
prefixes. This list establishes the initial witness set.

```json
{
  "v": "KERI10JSON...",
  "t": "icp",
  "b": ["BDg3H7Sr-eES0XWXiO8gitsD3olj-Z0C_4MhLESTR4tM",
        "BKmj2LPe8TrPRBCeVAdheWqHdZ0FlQmxXT-cMGV7TsDQ",
        "BIg1U6RF2Hy4DK4-t_MeG3pOEdVm0rFu5FyRZqpKg-go"],
  "bt": "2",
  ...
}
```

**Constraints at inception:**
- `b` MUST NOT contain duplicate entries
- If `b` is empty, `bt` MUST be `"0"`
- If `b` is non-empty, `bt` MUST satisfy `1 <= bt <= len(b)`

### 6.2 Witness Changes (Rotation)

Rotation events modify the witness list using differential fields:

| Field | Purpose | Constraints |
|-------|---------|-------------|
| `br`  | Witnesses to remove (cuts) | All MUST exist in current list; no duplicates |
| `ba`  | Witnesses to add (adds) | MUST NOT overlap with current list or `br`; no duplicates |

### 6.3 Derivation Algorithm

The new witness list after a rotation is computed as:

```
deriveBacks(current_witnesses, br, ba) → new_witnesses:

  1. Verify: no duplicates in br
  2. Verify: no duplicates in ba
  3. Verify: all entries in br exist in current_witnesses
  4. Verify: br ∩ ba = ∅  (cannot simultaneously remove and add)
  5. Verify: ba ∩ current_witnesses = ∅  (cannot add existing witness)
  6. new_witnesses = [w for w in current_witnesses if w not in br] + ba
  7. Verify: no duplicates in new_witnesses
  8. Return new_witnesses
```

**Example:**

```
current_witnesses = [W1, W2, W3]
br = [W2]        # remove W2
ba = [W4, W5]    # add W4 and W5
→ new_witnesses = [W1, W3, W4, W5]
```

### 6.4 Witness Ordering

The witness list is ordered. The position of a witness in the list determines
the index used in witness indexed signatures. When witnesses are added via
`ba`, they are appended to the end of the list (after removals). This ordering
is deterministic and reproducible by any party replaying the KEL.

### 6.5 Catching Up New Witnesses

When a rotation event adds new witnesses (via `ba`), the controller MUST send
the full KEL history to each new witness so that the witness can build its
local KERL. This catch-up process:

1. Iterates through all prior events in the KEL (from inception)
2. Sends each event (with attachments) to the new witness
3. Completes before requesting receipts from the new witness for the current
   event

---

## 7. TOAD (Threshold of Accountable Duplicity)

### 7.1 Definition

TOAD is the minimum number of witness receipts that a validator requires before
accepting a key event as sufficiently witnessed. It is encoded in the `bt`
field of establishment events.

TOAD provides a tunable security parameter: higher TOAD values require more
witnesses to collude in order to present inconsistent views, at the cost of
requiring more witnesses to be available.

### 7.2 Bounds

```
If wits is empty:
  bt MUST be 0

If wits is non-empty:
  1 <= bt <= len(wits)
```

### 7.3 Default Computation

When no explicit TOAD is provided, the default is computed using the `ample`
function, which selects an optimal threshold based on the number of witnesses:

```
ample(n) → default_toad:
  For a witness set of size n, returns a threshold that provides
  optimal Byzantine fault tolerance.
```

At inception, when no explicit TOAD is given and the witness list is non-empty,
the default is:

```
toad = max(1, ceil(len(wits) / 2))
```

### 7.4 TOAD Validation During Event Processing

The TOAD is validated differently depending on the event's relationship to the
local habitat:

- **Locally owned/witnessed/membered events:** TOAD is not enforced during
  initial event acceptance. The controller or local witness is trusted to
  eventually gather sufficient witness receipts.
- **Remote events (from non-local sources):** TOAD MUST be fully satisfied
  before the event is accepted into the KEL. If insufficient witness signatures
  are available, the event is placed in a **partial witness escrow** and a cue
  is emitted to query for additional witness receipts.

```
TOAD enforcement (remote events):
  if len(verified_witness_signatures) < toader.num:
    → Escrow event in partial-witness escrow
    → Emit query cue for witness receipts
    → Raise MissingWitnessSignatureError
```

### 7.5 Accountable Duplicity

The "accountable" in TOAD means that duplicitous behavior is attributable and
detectable. If a controller sends conflicting events to different witnesses:

- At most `toad - 1` witnesses can have a conflicting view without detection
- If `toad` or more witnesses agree on a version, at least one honest witness
  must have seen the same version (under the fault model)
- Any discrepancy in witness receipts constitutes provable evidence of
  controller duplicity

---

## 8. Witness AID Requirements

### 8.1 Non-Transferable AIDs (Recommended)

Witnesses SHOULD use non-transferable AIDs. A non-transferable AID:

- Uses a non-transferable prefix code (e.g., `B` for Ed25519 public key)
- Has an empty next-key digest list (`n = []`) at inception
- Cannot issue rotation events
- The AID prefix IS the public key (derivable directly)

**Benefits of non-transferable witness AIDs:**

1. **Simplicity:** No key management complexity — the witness prefix is the
   public key
2. **No rotation risk:** A witness cannot be compromised via key rotation
   attacks
3. **Direct verification:** Anyone can verify a witness signature using just
   the witness prefix as the public key, with no need to resolve the witness's
   own KEL
4. **Efficient receipts:** Witness indexed signatures use the witness list
   index directly, and the verifying key is derived from the prefix

### 8.2 Transferable AIDs (Supported)

Witnesses MAY use transferable AIDs, but this adds complexity:

- The witness's own KEL must be resolvable by anyone validating its receipts
- Receipts from transferable witnesses use the transferable receipt format
  (seal + indexed signatures) rather than witness indexed signatures
- Key rotation of the witness itself requires re-establishing trust

### 8.3 Witness Inception

When setting up a witness, the standard approach creates a non-transferable
identifier:

```
hab = hby.makeHab(name=alias, transferable=False)
```

This produces a `B`-prefixed AID where the prefix directly encodes the
Ed25519 public key.

---

## 9. Witness-Controller Interaction Model

### 9.1 Event Submission Flow

The standard witness receipting flow for a single event:

```
Controller                     Witness
    |                             |
    |  POST /receipts             |
    |  (event + signatures)       |
    |---------------------------->|
    |                             | 1. Parse event
    |                             | 2. Verify controller signatures
    |                             | 3. Apply first-seen policy
    |                             | 4. If accepted:
    |                             |    a. Log event
    |                             |    b. Create receipt (sign event)
    |                             |    c. Store receipt locally
    |  200 OK + receipt           |
    |<----------------------------|
    |                             |
    |  (or 202 Accepted if        |
    |   event needs escrow)       |
```

### 9.2 Full Receipting Workflow

When a controller publishes an event to its witness set:

```
1. Controller sends event to ALL witnesses in parallel
2. Each witness that accepts the event returns a receipt (200 OK)
   Witnesses that need to escrow return 202 Accepted
3. Controller collects receipts from responding witnesses
4. Controller sends cross-receipts: each witness receives the receipts
   from all OTHER witnesses
   - For inception/delegated inception: include witness endpoint OOBIs
   - For rotation with new witnesses (ba): include OOBIs for existing witnesses
5. Controller verifies it received at least TOAD receipts
```

### 9.3 Receipt Retrieval

Witnesses expose a GET endpoint for retrieving receipts:

```
GET /receipts?pre={aid}&sn={sequence_number}
GET /receipts?pre={aid}&said={event_said}

Response: receipt event + witness indexed signatures
```

This allows any party to retrieve the witness's receipt for a specific event
without resubmitting the event.

### 9.4 Witness Authentication of Events

Before receipting an event, a witness MUST verify:

1. **The event's controller signatures** satisfy the signing threshold (`kt`)
   from the current key state
2. **The event's sequence number** is consistent with the witness's local KEL
   (no gaps, no conflicts with first-seen events)
3. **The witness is designated** for this identifier (own prefix appears in
   the witness list for the identifier's current key state)

If any verification fails, the witness MUST NOT issue a receipt.

### 9.5 AID Filtering

A witness MAY be configured with a restricted set of AIDs it will serve. When
an `aids` filter is configured:

- The witness only accepts events from AIDs in the filter list
- Receipt requests for non-listed AIDs are rejected with an error
- This allows a witness to be dedicated to specific identifiers

---

## 10. Security Considerations

### 10.1 Witness Compromise

If a witness's private key is compromised, the attacker can:

- Create fraudulent receipts for events the witness never saw
- Potentially contribute to exceeding TOAD with false receipts

**Mitigation:** Non-transferable witness AIDs cannot be "rotated to" by an
attacker. The controller can rotate the compromised witness out of the witness
list via a rotation event with the compromised witness in `br`. The TOAD
mechanism ensures that compromise of fewer than `toad` witnesses does not
allow undetectable duplicity.

### 10.2 Witness Unavailability

If witnesses become unavailable:

- The controller cannot obtain sufficient receipts for new events
- Validators cannot verify events against the TOAD threshold
- The controller can rotate to new witnesses via a rotation event

**Mitigation:** The controller selects a witness set size and TOAD that
balances availability against security. More witnesses increase availability
but require more infrastructure.

### 10.3 Eclipse Attacks

An attacker might attempt to present different events to different witnesses
(eclipse attack). The first-seen policy ensures each witness commits to
exactly one version. Cross-receipt dissemination (Section 9.2) helps witnesses
detect inconsistencies.

### 10.4 Controller Duplicity

If a controller sends conflicting events at the same sequence number to
different subsets of witnesses, this is provable duplicity:

- Honest witnesses will have first-seen different versions
- Any validator collecting receipts from the full witness set will detect
  the inconsistency
- The TOAD ensures that a minimum quorum of witnesses must agree

### 10.5 Local vs Remote Event Processing

Events from local (protected) sources and remote (unprotected) sources are
processed differently:

- **Local events:** Accepted without full TOAD satisfaction (the controller
  trusts its own events and will gather receipts asynchronously)
- **Remote events:** Require full TOAD satisfaction before acceptance. Events
  with insufficient witness signatures are escrowed in a partial witness
  escrow (`escrowPWEvent`) until enough receipts are gathered

Additionally, a "misfit" escrow exists for events that arrive from remote
sources but belong to locally owned, locally witnessed, or locally delegated
identifiers. These events must first be promoted to local sourcing before
being accepted.

---

## 11. Implementation Notes

### 11.1 keripy Reference Architecture

The keripy implementation distributes witness functionality across several
components:

| Component | Module | Role |
|-----------|--------|------|
| `setupWitness` | `indirecting.py` | Initializes witness server with HTTP/TCP endpoints, parsers, and escrow processing |
| `WitnessStart` | `indirecting.py` | Doer that manages witness lifecycle: message parsing, escrow processing, and cue routing |
| `ReceiptEnd` | `indirecting.py` | HTTP endpoint handler for POST (submit event for receipting) and GET (retrieve existing receipt) |
| `Receiptor` | `agenting.py` | Controller-side doer that sends events to witnesses and collects/distributes receipts |
| `Hab.witness()` | `habbing.py` | Creates a witness receipt (indexed signature) for a given event |
| `Hab.receipt()` | `habbing.py` | Creates a general receipt for a given event |
| `Kevery.processReceipt()` | `eventing.py` | Validates and stores incoming receipts |
| `Kevery.fetchWitnessState()` | `eventing.py` | Resolves the witness list at a given sn by walking back to the nearest establishment event |

### 11.2 Database Storage

Receipts are stored in distinct database sub-databases depending on their type:

| Sub-DB | Contents |
|--------|----------|
| `wigs`  | Witness indexed signatures (Siger instances keyed by `(pre, dig)`) |
| `rcts`  | Non-transferable non-witness receipt couples `(verfer, cigar)` |
| `vrcs`  | Transferable receipt quadruples `(prefixer, seqner, saider, siger)` |
| `wits`  | Witness state (list of Prefixer) keyed by `(pre, dig)` at each establishment event |

### 11.3 Escrow Types for Receipts

| Escrow | Condition | Resolution |
|--------|-----------|------------|
| Unverified receipt (`ure`) | Receipt arrives before the receipted event | Process when the event arrives |
| Unverified witness receipt (`uwe`) | Witness indexed receipt arrives before the receipted event | Process when the event arrives |
| Unverified transferable receipt (`vre`) | Transferable receipt whose receipter's establishment event is unknown | Process when the receipter's KEL is resolved |
| Partial witness escrow (`pwe`) | Event has valid controller signatures but insufficient witness signatures | Process when additional witness receipts arrive |

### 11.4 Witness Server Endpoints

A standard keripy witness exposes:

| Path | Method | Purpose |
|------|--------|---------|
| `/` | POST | General CESR message ingestion (KEL events, replies, exchanges) |
| `/receipts` | POST | Submit an event for witness receipting; returns receipt or 202 |
| `/receipts` | GET | Retrieve an existing receipt by `pre` and `sn` or `said` |
| `/query` | GET/POST | Query witness for key state and other information |

### 11.5 Cross-Version Support

The witness implementation supports both KERI protocol version 1.0 and 2.0.
Version 2.0 rotation events include the `c` (config) field, while version 1.0
does not. The witness MUST parse events according to the version indicated in
the `v` field.
