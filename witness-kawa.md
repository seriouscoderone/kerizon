# KAWA: KERI Agreement Algorithm for Witnesses

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Define the KAWA (KERI's Algorithm for Witness Agreement) protocol, a BFT single-phase agreement mechanism among designated witnesses that provides immune agreement on key events.
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation

---

This document specifies KAWA, the single-phase agreement algorithm used
exclusively by witnesses in the KERI protocol. KAWA guarantees that at most
one sufficient agreement can occur for any given key event, providing immune
agreement without requiring multi-phase commit protocols. Watchers do NOT
participate in KAWA; they operate in a separate duplicity detection layer.

---

## 1. Purpose and Scope

KAWA solves a specific problem: ensuring that a controller cannot successfully
publish two different versions of the same key event (at the same sequence
number) such that both versions receive sufficient witness support.

**What KAWA covers:**
- Agreement among designated witnesses on key events
- First-seen policy enforcement
- Immunity from controller-initiated equivocation

**What KAWA does NOT cover:**
- Duplicity detection (handled by watchers; see watcher specifications)
- Key compromise recovery (handled by rotation events; see [KEL Core](kel-core.md) Section 23)
- Validator-side verification (validators enforce TOAD independently)

**Why KAWA is witness-exclusive:** Watchers observe and detect duplicity after
the fact. Witnesses actively participate in agreement by receipting events.
These are distinct roles with distinct trust assumptions.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Immune Agreement** | A guarantee that at most one sufficient agreement occurs for a given event slot (prefix, sequence number). Even a dishonest controller cannot produce two distinct events at the same sequence number that both achieve sufficient witness support. |
| **Sufficient Agreement** | A set of witness receipts whose size meets or exceeds the threshold M (TOAD). |
| **TOAD** | Threshold of Accountable Duplicity. The minimum number of witness receipts a validator requires before accepting an event as sufficiently witnessed. Set by the controller in the `bt` field. |
| **Proper KERL** | A Key Event Receipt Log that has been verified as consistent with all prior events by every non-faulty witness that contributed receipts. |
| **First-Seen** | The policy by which a witness accepts only the first valid event it receives at a given sequence number and permanently rejects all alternatives. |
| **N** | Total number of designated witnesses for an identifier. |
| **M** | Agreement threshold (TOAD). Minimum witness receipts required. |
| **F** | Maximum number of duplicitous (dishonest) witnesses that can be tolerated. |
| **F\*** | Maximum number of unavailable (offline/unreachable) witnesses that can be tolerated. F* = N - M. |

---

## 3. System Model

### 3.1 Participants

KAWA involves exactly two roles:

1. **Controller** -- Creates and signs key events, publishes them to witnesses
2. **Witnesses** -- Designated non-transferable identifier nodes that receipt events

Validators are NOT participants in the KAWA protocol. They consume the output
of KAWA (receipted events) but do not influence agreement.

### 3.2 Witness Designation

Witnesses are designated in the controller's inception event (`b` field) and
may be modified by rotation events (`br` and `ba` fields). Each witness is
identified by a non-transferable AID (see [KEL Core](kel-core.md) Section 13).

### 3.3 Fault Bounds

Given N witnesses and threshold M (TOAD):

```
F* = N - M          Maximum unavailable witnesses
F  < M              Maximum duplicitous witnesses (strict inequality)
N  >= M + F*         Witness count must support both fault types
```

For immune agreement to hold, the number of duplicitous witnesses F must
satisfy F < M. If F >= M, a dishonest controller colluding with F witnesses
could produce two sufficient agreements -- but this would be detectable via
duplicity detection (watchers).

### 3.4 BFT Constraint

The `ample()` function computes the default TOAD satisfying BFT requirements:

```
ample(n, f=None, weak=True) -> int

Given N witnesses:
  f = max(1, floor((N-1) / 3))    -- maximum fault tolerance
  Constraint: N >= 3*f + 1
  M = ceil((N + f + 1) / 2)       -- minimum sufficient majority
```

Reference: `src/keri/core/eventing.py:65-102`

| N | f | M (TOAD) | F* = N-M | Description |
|---|---|----------|----------|-------------|
| 1 | 0 | 1 | 0 | Single witness, no fault tolerance |
| 2 | 0 | 2 | 0 | Both witnesses must agree |
| 3 | 0 | 2 | 1 | One may be unavailable |
| 4 | 1 | 3 | 1 | One fault tolerated |
| 5 | 1 | 3 | 2 | One fault, two may be unavailable |
| 6 | 1 | 4 | 2 | One fault tolerated |
| 7 | 2 | 5 | 2 | Two faults tolerated |
| 10 | 3 | 7 | 3 | Three faults tolerated |

---

## 4. Agreement Protocol

### 4.1 Why Single-Phase

Traditional BFT consensus (PBFT, Raft) uses multi-phase commit to ensure
agreement on a shared, ordered sequence of operations. KAWA does not require
multi-phase commit because:

1. **Key events are idempotent authorization operations.** Applying the same
   valid event twice produces the same key state. There is no state mutation
   that requires rollback.

2. **No shared ordering.** Each identifier has its own independent event
   sequence. Witnesses do not need to agree on a global order across
   identifiers.

3. **First-seen is sufficient.** A witness only needs to accept or reject an
   event based on whether it is the first valid event at that sequence number.
   No negotiation or voting round is required.

### 4.2 Protocol Steps

```
1. Controller creates and signs event E at sequence number S
2. Controller publishes E to each of the N designated witnesses
3. Each witness independently:
   a. Validates E (signatures, prior digest chain, SAID binding)
   b. Checks first-seen: has it already accepted an event at S?
      - If YES: reject E (even if E is identical to what was stored)
      - If NO: accept E, store it, sign a receipt
   c. Returns receipt (signed acknowledgment) to controller
4. Controller collects receipts
5. Controller propagates receipts to other witnesses
   (so each witness knows which other witnesses have receipted)
```

The protocol is single-phase: each witness makes an independent, irrevocable
accept/reject decision with no coordination among witnesses.

### 4.3 First-Seen Policy

The first-seen rule is the foundation of KAWA's immunity guarantee:

**"First seen, always seen, never unseen."**

Once a witness has accepted an event at a given (prefix, sequence number), it:
- Permanently stores that event version
- Signs a receipt for that event version
- Rejects ALL other events at that same (prefix, sequence number), including
  identical copies submitted later

This is enforced via the first-seen event log (FEL). In keripy, the
`db.fels.appendOn()` method provides a non-idempotent append that records the
first-seen ordinal (`fn`) for each accepted event.

Reference: `src/keri/core/eventing.py:3386-3387` -- `fn = self.db.fels.appendOn(keys=serder.preb, val=serder.saidb)`

### 4.4 Controller Role in Receipt Collection

The controller is the active coordinator in KAWA. It:

1. Publishes the event to all witnesses
2. Collects individual receipts from each witness
3. Propagates each witness's receipt to all other witnesses

This is implemented by the `Receiptor` and `WitnessReceiptor` classes in
`src/keri/app/agenting.py`. The controller constructs receipt messages
(`eventing.receipt()`) with attached non-transferable receipt couples or
witness indexed signatures and sends them to each witness in the set.

---

## 5. Immunity Property

### 5.1 Definition

KAWA provides **immune agreement**: given N witnesses with threshold M and at
most F < M duplicitous witnesses, at most ONE event version at any sequence
number can achieve a sufficient agreement (M or more receipts from distinct
witnesses).

### 5.2 Proof Sketch

Suppose a dishonest controller publishes two different events E1 and E2 at
the same sequence number S.

- Let W1 = set of witnesses that receipt E1
- Let W2 = set of witnesses that receipt E2
- Let D = set of duplicitous witnesses (|D| = F < M)

By the first-seen policy, an honest witness receipts at most one of E1 or E2.
Therefore, honest witnesses in W1 and W2 are disjoint:

```
(W1 \ D) ∩ (W2 \ D) = {}
```

For both to achieve sufficient agreement:

```
|W1| >= M  and  |W2| >= M
```

The total witnesses needed (excluding double-counted duplicitous ones):

```
|W1 \ D| + |W2 \ D| + |D| >= (M - F) + (M - F) + F = 2M - F
```

For this to be feasible: `2M - F <= N`, i.e., `M <= (N + F) / 2`.

But the ample formula guarantees `M >= ceil((N + F + 1) / 2)`, which means
`M > (N + F) / 2`. Contradiction. Therefore at most one sufficient agreement
can occur.

### 5.3 What Immunity Does NOT Guarantee

Immunity guarantees uniqueness of sufficient agreement, NOT that:
- The controller is honest (it may attempt equivocation)
- All witnesses are reachable (F* may be unavailable)
- A compromised controller colluding with F >= M witnesses cannot succeed
  (this requires duplicity detection via watchers)

---

## 6. Security Properties and Limitations

### 6.1 Properties Provided

| Property | Guarantee |
|----------|-----------|
| **Agreement uniqueness** | At most one version of an event at a given sn achieves M receipts |
| **Availability** | Any non-faulty witness with a proper agreement keeps it in its KERL and provides it on demand |
| **Consistency** | A proper agreement has been verified as consistent with all prior events by every non-faulty witness |
| **Accountability** | If a controller equivocates, duplicitous witnesses are identifiable by their conflicting receipts |

### 6.2 Limitations

| Limitation | Explanation |
|------------|-------------|
| **Controller + F >= M witnesses collude** | Immunity breaks. Detected post-hoc by watchers. |
| **All witnesses offline** | No agreement possible. Controller must wait or rotate witnesses. |
| **Network partition** | A partition isolating < M witnesses from the controller prevents agreement on their side, but does not create false agreement. |
| **Witness key compromise** | A compromised witness key allows impersonation. Mitigated by non-transferable identifiers (no rotation risk). |

### 6.3 Comparison with Traditional BFT

| Aspect | Traditional BFT (PBFT) | KAWA |
|--------|----------------------|------|
| **Phases** | 3 (pre-prepare, prepare, commit) | 1 (receipt) |
| **Ordering** | Global total order | Per-identifier sequence only |
| **State machine** | Replicated deterministic FSM | Independent per-witness accept/reject |
| **Idempotency** | Operations may not be idempotent | Key events are idempotent |
| **Leader** | Rotating leader | Controller is always the proposer |
| **Liveness** | Guaranteed under 2f+1 | Guaranteed under M honest witnesses |
| **View change** | Complex protocol | Witness rotation via `rot` event |

---

## 7. Relationship to Duplicity Detection

KAWA and duplicity detection are complementary but independent mechanisms.

```
KAWA (Witnesses)                 Duplicity Detection (Watchers)
─────────────────                ──────────────────────────────
Prevents: two sufficient         Detects: controller equivocation
  agreements                       even when KAWA immunity holds

Operates: during event           Operates: after event publication
  publication                      (continuous monitoring)

Participants: controller,        Participants: watchers, validators
  witnesses only

Guarantee: at most ONE            Guarantee: if duplicity occurred,
  sufficient agreement              it will be discovered
```

When a controller equivocates (publishes two versions of an event), KAWA
ensures that at most one version can achieve sufficient witness support. But
the controller may still have sent different versions to different witnesses.
Watchers detect this by collecting and comparing receipts across witnesses.

The TOAD is a **validator-selected** threshold for how much witness support
the validator requires. A validator MAY set its acceptance threshold higher
than the controller's TOAD to increase its confidence. The validator's TOAD
determines its exposure to accountable duplicity.

---

## 8. Implementation Notes

### 8.1 keripy Reference

The KAWA protocol is implemented across several components:

| Component | File | Role |
|-----------|------|------|
| `ample()` | `src/keri/core/eventing.py:65` | Computes BFT threshold M |
| `Kever.logEvent()` | `src/keri/core/eventing.py:3319` | Records first-seen ordinal via `db.fels.appendOn()` |
| `Kevery.processReceipt()` | `src/keri/core/eventing.py:4155` | Validates and stores witness receipts |
| `Receiptor` | `src/keri/app/agenting.py:29` | Orchestrates receipt collection and propagation |
| `WitnessReceiptor` | `src/keri/app/agenting.py:287` | Full receipt cycle: publish, collect, propagate |

### 8.2 First-Seen Ordinal Tracking

Each accepted event receives a monotonically increasing first-seen ordinal
(`fn`) within its prefix's FEL. This ordinal is distinct from the event's
sequence number (`sn`):

- `sn` -- protocol-defined position in the KEL (may have gaps during recovery)
- `fn` -- local first-seen position in the FEL (strictly monotonic, no gaps)

The Kever tracks this as `self.fner` (a `Number` instance). The ordinal is
recorded via `self.db.fels.appendOn()` which is non-idempotent -- calling it
twice for the same event returns `None` on the second call, preventing
duplicate first-seen entries.

Reference: `src/keri/core/eventing.py:1648-1649`, `src/keri/core/eventing.py:3386-3398`

### 8.3 TOAD Validation

TOAD validation is performed during inception and rotation:

```
if wits is not empty:
    assert 1 <= toad <= len(wits)
else:
    assert toad == 0
```

If no explicit TOAD is provided, the default is computed via `ample()`:

```python
if toad is None:
    if not wits:
        toad = 0
    else:
        toad = ample(len(wits))
```

Reference: `src/keri/core/eventing.py:519-537`
