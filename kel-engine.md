# KEL Engine: Event Processing and Escrow

**Version:** 0.1.1-draft
**Status:** Draft
**Part of:** [KEL Specification](kel-specification.md)
**Dependencies:** [KEL Crypto](kel-crypto.md), [KEL Core](kel-core.md)
**Interface consumed:** `KeyStateProvider` (from Core)
**Interface exported:** `EventProcessor` — submit events, get back state or escrow reason

---

This document defines the event ingestion pipeline — everything that happens
when an event arrives at a KERI node. Processing, escrow, duplicity detection,
ordering, and cue emission.

---

## 1. Kevery: The Event Processing Facility

The Kevery is a factory and processor that:
- Maintains a collection of Kevers (one per known AID)
- Receives serialized events and dispatches them for processing
- Manages escrows for incomplete or out-of-order events
- Generates cues for external action (receipting, notification)

```
Kevery
  .kevers                -- dict[string, Kever]: AID prefix → Kever
  .db                    -- EventDatabase: persistent storage
  .cues                  -- deque: output notifications
  .lax                   -- bool: promiscuous mode flag
  .local                 -- bool: local event source flag
  .cloned                -- bool: cloned replay mode
  .direct                -- bool: cue receipts directly
  .check                 -- bool: idempotent check mode
```

---

## 2. Processing Modes

| Mode | Parameter | Effect |
|------|-----------|--------|
| **Lax** | `lax=True` | Accept all events regardless of local prefix ownership (promiscuous) |
| **Local** | `local=True` | Events from protected source; affects escrow behavior |
| **Cloned** | `cloned=True` | Replay mode: use attached datetimes instead of current time |
| **Direct** | `direct=True` | Generate receipt cues for witnessed events |
| **Check** | `check=True` | Don't assign new first-seen ordinals (idempotent verification) |

---

## 3. Event Dispatch Algorithm

```
processEvent(serder, sigers, wigers=None, delseqner=None, deldiger=None):

  pre = serder.i          -- AID prefix
  ilk = serder.t          -- event type
  sn  = int(serder.s, 16) -- sequence number

  -- PATH 1: First inception (pre NOT in kevers) --
  if pre not in kevers:
    if ilk not in {icp, dip}:
      → Reject: "Out of order — no inception found"
    Create new Kever from serder + sigers + wigers
    kevers[pre] = new_kever
    → Cue: receipt, notice, or witness as appropriate
    return

  -- PATH 2: Subsequent events (pre already in kevers) --
  kever = kevers[pre]
  expected_sn = kever.sn + 1

  if sn == 0:
    -- Duplicate inception --
    if serder.said == kever.serder.said:
      → Accept additional signatures (idempotent logEvent)
    else:
      → Likely duplicitous: escrow in LDE
    return

  if sn > expected_sn:
    -- Out of order --
    → Escrow in OOE
    return

  if sn == expected_sn OR is_valid_recovery(ilk, sn, kever):
    -- In-order or recovery --
    kever.update(serder, sigers, wigers, ...)
    → Cue: receipt, notice, or witness
    return

  -- Likely duplicitous or stale --
  if event_at_sn has same SAID:
    → Accept additional signatures (idempotent)
  else:
    → Likely duplicitous: escrow in LDE
```

---

## 4. First-Seen Ordering (FEL)

The first-seen ordinal (`fn`) is a monotonically increasing number assigned
when an event is first accepted into the KEL. Unlike sequence numbers,
first-seen ordinals never have gaps and reflect the actual order of acceptance.

```
fn assignment:
  fn = db.fels.appendOn(prefix, said)
  -- Appends to the First-seen Event Log
  -- Returns the next available fn for this prefix
  -- Non-idempotent: only assigned once per event
```

**fn vs sn distinction:**

| Property | sn (sequence number) | fn (first-seen ordinal) |
|----------|---------------------|------------------------|
| Determined by | Event creator | Accepting processor |
| Ordering | May have gaps (recovery) | Always contiguous |
| Uniqueness | Multiple events possible at same sn (duplicity) | One fn per accepted event |
| Purpose | Protocol ordering | Replay ordering |
| Recovery behavior | Can rewind to override ixn | Continues incrementing |

**Example with recovery:**

```
fn  sn  ilk
0   0   icp    Normal inception
1   1   ixn    Normal interaction
2   2   ixn    Normal interaction
3   3   ixn    Normal interaction
4   1   rot    Recovery rotation (sn rewinds, fn continues)
5   2   ixn    Builds on recovery
```

---

## 5. Duplicity Detection

Duplicity occurs when different events exist at the same sequence number for
the same AID. This indicates either controller error or malicious behavior.

**Detection:** When processing an event at `sn` where a different event
(different SAID) already exists at that `sn`, the Kevery:
1. Escrows the conflicting event in the Likely Duplicitous Escrow (LDE)
2. Raises `LikelyDuplicitousError`
3. Does NOT update key state

**Exception:** A rotation event at the same `sn` as an interaction event MAY
be a valid recovery (see [Core](kel-core.md) Section 12), not duplicity.

---

## 6. Cue System

The Kevery generates cues — notification messages pushed to an output deque —
for external components to act upon:

| Cue kind | Trigger | External action |
|----------|---------|-----------------|
| `receipt` | Event accepted (direct/lax mode) | Generate and send receipt to witnesses |
| `notice` | Event accepted (indirect mode) | Notify controller of acceptance |
| `witness` | Local event with witnesses | Initiate witness protocol |
| `noticeBadCloneFN` | Clone fn mismatch | Alert divergence between live and cloned streams |

---

## 7. Escrow Concept

An event enters escrow when it passes some initial validation but cannot be
fully accepted due to missing information:
- Not enough signatures yet (other signers haven't contributed)
- Witness receipts haven't arrived
- Prior event in the sequence hasn't been received
- Delegation seal not found in delegator's KEL

The escrow system holds these events with their partial data and periodically
retries processing. Each escrow type has a timeout after which the event is
discarded.

**Note on timeouts:** The timeout values listed below are reference
implementation defaults from keripy, not normative requirements. The KERI
specification does not mandate specific timeout values. Implementations MAY
use different timeout policies appropriate to their deployment context.

---

## 8. Escrow Types

### 8.1 Partial Signature Escrow (PSE)

| Property | Value |
|----------|-------|
| **Trigger** | Controller signatures verify but count < signing threshold |
| **Resolution** | Additional signatures arrive; reprocess and threshold met |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

The most common escrow for multi-signature identifiers. When a multi-sig
event is created, each signer contributes their signature independently. The
event sits in PSE until enough signatures accumulate.

### 8.2 Partial Witness Escrow (PWE)

| Property | Value |
|----------|-------|
| **Trigger** | Controller signature threshold met, but witness receipt count < TOAD |
| **Resolution** | Witness receipts arrive; reprocess and TOAD met |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

After a controller publishes an event to witnesses, receipts arrive
asynchronously. The event moves from PSE → PWE once controller sigs are
sufficient, then exits PWE when enough witness receipts arrive.

### 8.3 Out-of-Order Escrow (OOE)

| Property | Value |
|----------|-------|
| **Trigger** | Event sn > expected next sn (gap in sequence) |
| **Resolution** | Missing prior events arrive; reprocess in order |
| **Timeout** | 1200 seconds (20 minutes) |
| **Storage key** | (prefix, sn) → event SAID |

Occurs when events arrive out of sequence (e.g., receive sn=5 before sn=4).
Shorter timeout than other escrows because out-of-order delivery should
resolve quickly.

### 8.4 Likely Duplicitous Escrow (LDE)

| Property | Value |
|----------|-------|
| **Trigger** | Different event (different SAID) at same sn as an existing event |
| **Resolution** | External resolution (human review, automated policy) |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

The most serious escrow type. Indicates potential controller compromise or
malicious behavior. Events in LDE are NOT automatically promoted — they
require explicit external resolution.

### 8.5 Pending Delegation Escrow (PDE)

| Property | Value |
|----------|-------|
| **Trigger** | Delegated event fully signed/witnessed but delegation seal not found in delegator's KEL |
| **Resolution** | Delegator's anchoring event arrives; reprocess |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

Delegation seal lookup uses `pin()` (not `put()`) — allowing seal information
to be updated/replaced as the delegator's KEL evolves.

### 8.6 Delegable Escrow

| Property | Value |
|----------|-------|
| **Trigger** | Local delegation event awaiting controller approval |
| **Resolution** | Controller approves delegation via seal in own KEL |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

For locally-controlled delegators: holds delegated events from delegates until
the local controller decides to anchor the approval seal.

### 8.7 Misfit Source Escrow

| Property | Value |
|----------|-------|
| **Trigger** | Event source (local/remote) doesn't match expected source for this prefix |
| **Resolution** | Source classification changes; reprocess |
| **Timeout** | 3600 seconds (1 hour) |
| **Storage key** | (prefix, sn) → event SAID |

Handles events that arrive from an unexpected source type. For example, an
event for a locally-controlled identifier arriving from a remote channel.

---

## 9. Escrow Lifecycle

```
Event arrives
    │
    ▼
┌─────────────┐
│  Validate   │──── Structurally invalid ──→ REJECT
│  (partial)  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Missing    │──── Yes ──→ ESCROW (with reason)
│  dependency?│              │
└──────┬──────┘              │
       │ No                  ▼
       ▼               ┌──────────┐
┌─────────────┐        │ Periodic │──→ Timeout? ──→ DISCARD
│   ACCEPT    │        │ reprocess│
│  (log event,│        └─────┬────┘
│   assign fn)│              │ Resolved
└─────────────┘              │
       ▲                     │
       └─────────────────────┘
```

---

## 10. Processing Order

Escrow processing runs in a specific order to maximize resolution:

1. **Out-of-Order (OOE)** — Process first because resolved OOE events may
   unblock other escrows
2. **Partial Signatures (PSE)** — Additional signatures may have arrived
3. **Partial Witnesses (PWE)** — Witness receipts may have arrived
4. **Pending Delegation (PDE)** — Delegator events may have arrived
5. **Delegable** — Local approval may have been given
6. **Likely Duplicitous (LDE)** — Check if external resolution occurred

**Unverified receipt escrows** (for receipts that arrived before their
receipted events) are processed as their target events arrive:
- **Unverified Witness Receipts (UWE)**: Receipt before event → escrow, then
  apply when event accepted
- **Unverified Non-Transferable Receipts (URE)**: Endorsement before event
- **Unverified Transferable Receipts (VRE)**: Validator receipt before
  receiptor's est event

---

## 11. CESR Attachment Framing

CESR attachment groups use a two-tier counting structure for controller
indexed signatures. The outer counter indicates the number of signature
groups, and each inner counter indicates the number of signatures in that
group.

**Example (multisig with 2 signing groups):**

```
-AAB    <- outer: 2 groups of controller indexed signatures
-AAA    <- Group 1: 0 signatures
-AAC    <- Group 2: 2 signatures
<sig1>
<sig2>
```

The outer `-A` counter specifies how many inner `-A` groups follow. Each
inner group corresponds to a signer in a multi-signature scheme. This
two-tier structure allows partial signature collection: groups with no
signatures yet contributed are represented as `-AAA` (count 0).
