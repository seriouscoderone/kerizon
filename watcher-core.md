# Watcher Core Protocol

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Specification of the KERI Watcher role, key state adjudication, and the DiffState model used by validators to independently verify KEL consistency across a watcher pool.
**Normative basis:** [KERI Specification](https://trustoverip.github.io/kswg-keri-specification/)
**Cross-checked against:** keripy reference implementation (`watching.py`, `querying.py`, `eventing.py`)

---

## 1. Purpose and Scope

This document specifies the Watcher infrastructure that validators deploy to independently monitor Key Event Logs (KELs). Watchers provide validators with a second source of truth beyond the controller's designated witnesses, enabling detection of duplicitous behavior and key state divergence.

The spec covers:

- The Watcher role and how it differs from the Witness role
- The DiffState model for comparing remote and local key state
- The Adjudicator algorithm for evaluating watcher consensus
- Cue types emitted during adjudication
- Watcher pool architecture and operational considerations

It does not cover the Juror/Jury/Judge duplicity detection hierarchy, which is specified in [Watcher Duplicity](watcher-duplicity.md).

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Watcher** | A validator-controlled service that maintains a duplicate copy of a KERL and independently verifies key state for watched AIDs. |
| **DiffState** | A record of the difference between a remotely reported KeyStateRecord and the local KeyStateRecord for the same AID. |
| **Stateage** | An enumeration of four possible comparison states: `even`, `ahead`, `behind`, `duplicitous`. |
| **Adjudicator** | A component that compares key state from a watcher set against local state using a per-adjudication threshold. |
| **Watcher Receipt** | A signed receipt from a watcher acknowledging an event. Also called an "ersatz receipt" because it provides verification outside the controller's designated witness set. |
| **TOAD** | Threshold of Accountable Duplicity. In adjudication, the minimum number of watchers that must agree on new key state before the adjudicator accepts it. |
| **Watched AID** | An Autonomic Identifier whose KEL a watcher is monitoring on behalf of a validator. |

---

## 3. Watcher vs Witness

Watchers and witnesses both maintain copies of KELs. They serve fundamentally different roles in the KERI architecture.

| Property | Witness | Watcher |
|----------|---------|---------|
| **Designated by** | Controller (in KEL establishment events) | Validator (outside KEL) |
| **Composition visibility** | Public — embedded in KEL events | May be confidential |
| **Consensus protocol** | Participates in KAWA (KERI Agreement Algorithm for Watchers) | Does NOT participate in KAWA |
| **Scope** | AID-specific (bound to controller's KEL) | Any/all AIDs shared with it |
| **Accountability** | Accountable to controller via TOAD | Accountable to validator only |
| **Receipts** | Witness receipts are part of KEL validation | Watcher receipts are supplementary ("ersatz") |
| **Infrastructure ownership** | Controller infrastructure | Validator infrastructure |

Key distinction: witnesses are part of the controller's security model (their receipts satisfy the controller's TOAD). Watchers are part of the validator's verification model (their consensus is evaluated by the validator's adjudicator).

---

## 4. Watcher Role and Designation

### 4.1 Validator-Controlled Infrastructure

A watcher is deployed and managed by the validator, not the controller. The validator selects which watchers to use and may change its watcher set at any time without affecting the KEL of any watched AID. This separation ensures that the validator's verification is independent of the controller's designated infrastructure.

### 4.2 Confidentiality

Unlike witness composition, which is published in KEL establishment events, a validator's watcher composition MAY be kept confidential. This provides privacy for the validator's verification strategy and prevents targeted attacks on the validator's watcher infrastructure.

### 4.3 AID Observation

A validator configures which AIDs each watcher should observe. The observation relationship is tracked in the `obvs` database, keyed by `(controller_pre, watcher_aid, watched_aid)`. Each observation record includes an `enabled` flag that can toggle monitoring on or off.

### 4.4 KEL Acquisition

Watchers acquire KELs by querying witnesses and other watchers. A watcher follows the same first-seen policy as the rest of the KERI protocol: once an event is accepted at a given sequence number, that version is retained as authoritative. Any subsequently received event at the same sequence number with a different digest is treated as potential evidence of duplicity.

---

## 5. First-Seen Policy (Watcher Variant)

Watchers apply the same first-seen principle that underpins all KERI validation:

> **First seen, always seen, never unseen.**

For a watcher, this means:

1. The first version of an event received and verified at a given `(pre, sn)` pair becomes the watcher's accepted version.
2. If a second version of the same event (same `pre` and `sn` but different SAID) arrives, the watcher flags it as potential duplicity and retains both versions as evidence.
3. The watcher never replaces an accepted event with a later-arriving alternative.

This policy is identical to the witness and validator first-seen policy. The difference is scope: a watcher applies this policy on behalf of the validator, across all watched AIDs, providing an independent verification layer.

### 5.1 Watcher Receipts

A watcher MAY issue signed receipts for events it has accepted. These "ersatz receipts" provide additional assurance to the validator that the event was seen by the watcher, but they do not count toward the controller's TOAD. Watchers have a strong incentive to share KELs widely because doing so strengthens their first-seen advantage: the earlier a watcher sees an event, the more likely its accepted version is the legitimate one.

### 5.2 Watcher-to-Watcher Exchange

Watchers in a pool may exchange KEL data and receipts with each other. This peer exchange enables:

- Faster propagation of legitimate events across the watcher pool
- Cross-verification between watchers
- Detection of network partitioning or targeted withholding

A watcher pool MAY optionally employ KAWA for internal agreement, though this is not required by the core protocol.

---

## 6. Key State Adjudication

Adjudication is the process by which a validator compares key state reported by its watcher set against its own local key state to determine consistency, detect updates, and flag duplicity.

### 6.1 DiffState Model

A `DiffState` record captures the difference between a remotely reported key state and the local key state for a single AID as reported by a single watcher.

```
DiffState:
    pre   : str        # AID being watched
    wit   : str        # AID of the reporting watcher
    state : Stateage   # Comparison result: even | ahead | behind | duplicitous
    sn    : int        # Sequence number from the remote key state
    dig   : str        # Digest of the latest event from the remote key state
```

The `state` field is computed by the `diffState` function, which compares local and remote KeyStateRecords:

| Condition | Stateage |
|-----------|----------|
| Same `sn` AND same `dig` | `even` — watcher agrees with local state |
| Same `sn` BUT different `dig` | `duplicitous` — same sequence number, different event |
| Local `sn` > remote `sn` | `behind` — watcher has not yet seen the latest event |
| Local `sn` < remote `sn` | `ahead` — watcher reports a newer event than local state |

The `duplicitous` state at the DiffState level is the most critical signal: it means the watcher and the local node have both accepted events at the same sequence number, but the events have different SAIDs (content digests). This is direct evidence of a forked KEL.

### 6.2 Adjudication Algorithm

The `Adjudicator` processes adjudication requests for a specific watched AID. The algorithm proceeds as follows:

1. **Gather watchers.** Enumerate all enabled watchers for the watched AID from the `obvs` database.

2. **Set threshold.** If a TOAD is provided, use it. Otherwise, default to the total number of watchers (unanimous consensus required).

3. **Collect key state.** For each watcher, retrieve the most recent KeyStateNotice (KSN) from the `knas`/`ksns` databases. Compute a `DiffState` for each watcher that has reported.

4. **Classify.** Partition the DiffState records into three groups:
   - `dups` — states where `state == duplicitous`
   - `ahds` — states where `state == ahead`
   - `bhds` — states where `state == behind`
   - (Remaining states are `even`)

5. **Evaluate.** Apply the decision tree described in section 6.4.

### 6.3 Adjudication Threshold

The adjudication threshold (TOAD) determines how many watchers must agree on new key state before the adjudicator accepts it as a `keyStateUpdate`. The threshold provides a tunable tradeoff:

- **High threshold (= watcher count):** Requires all watchers to agree. Maximum safety, but a single unresponsive watcher blocks updates.
- **Low threshold:** Allows faster detection of updates, but reduces the consensus bar. Must remain above a super-majority to prevent a compromised minority from forcing false updates.

If no threshold is provided, the adjudicator defaults to requiring all watchers to agree (threshold equals watcher count).

Constraint: the threshold MUST NOT exceed the number of enabled watchers. If it does, the adjudicator raises a validation error.

### 6.4 Cue Types and Responses

The adjudicator emits exactly one cue per adjudication round. The cue type (kin) depends on the classification from step 4:

#### `keyStateDuplicitous`

**Trigger:** Any watcher reports a DiffState with `state == duplicitous`, OR watchers that are ahead of local state disagree with each other (multiple distinct digests among the `ahead` group).

**Payload:**
```
kin  : "keyStateDuplicitous"
cid  : controller AID (adjudicator's own identifier)
oid  : watched AID
wids : set of all watcher AIDs
dups : list of DiffState records showing duplicity
```

**Response:** This is the most severe cue. Local key state is NOT updated. The duplicity must be reported for investigation. Controller intervention is required to reconcile.

**Priority:** Duplicity detection takes priority over all other states. If any `dups` exist, the adjudicator emits `keyStateDuplicitous` regardless of other states.

#### `keyStateUpdate`

**Trigger:** No duplicity detected. One or more watchers are ahead of local state, and:
- All ahead watchers agree on the same digest (single value in the set of ahead digests)
- The count of ahead watchers meets or exceeds the threshold

**Payload:**
```
kin    : "keyStateUpdate"
cid    : controller AID
oid    : watched AID
wids   : set of all watcher AIDs
sn     : sequence number from the new state
aheads : list of DiffState records from ahead watchers
```

**Response:** Consumers are safe to retrieve the new key state from any of the watchers listed in `aheads`. One watcher is selected at random for the `sn` field in the cue.

#### `keyStateLagging`

**Trigger:** No duplicity detected, no watchers are ahead, but some watchers are behind local state.

**Payload:**
```
kin    : "keyStateLagging"
cid    : controller AID
oid    : watched AID
wids   : set of all watcher AIDs
behind : list of DiffState records from behind watchers
```

**Response:** The lagging watchers may have connectivity issues or may not have access to the watched AID's witnesses. The validator should check that lagging watchers can reach the AID's witness infrastructure.

#### `keyStateConsistent`

**Trigger:** No duplicity, no watchers ahead, no watchers behind. All responding watchers agree with local key state.

**Payload:**
```
kin    : "keyStateConsistent"
cid    : controller AID
oid    : watched AID
wids   : set of all watcher AIDs
states : list of all DiffState records (all `even`)
```

**Response:** No action required. The validator's local key state is consistent with the watcher pool. Note that consistency is reported relative to the number of watchers that responded, not the total number of watchers.

### 6.5 Decision Tree Summary

```
┌─ Any duplicitous?
│   YES → keyStateDuplicitous
│   NO  ─┬─ Any ahead?
│         │   YES ─┬─ Ahead watchers disagree (multiple digests)?
│         │        │   YES → keyStateDuplicitous
│         │        │   NO  ─┬─ Count(ahead) >= threshold?
│         │        │        │   YES → keyStateUpdate
│         │        │        │   NO  → (no cue emitted; wait for more watchers)
│         │   NO  ─┬─ Any behind?
│         │        │   YES → keyStateLagging
│         │        │   NO  → keyStateConsistent
```

Note: when watchers are ahead but their count does not meet the threshold, and they all agree on the same digest, no cue is emitted. The adjudicator waits for additional watcher responses before making a determination.

---

## 7. Watcher Pool Architecture

### 7.1 Pool Composition

A validator's watcher pool SHOULD include multiple independent watchers to provide redundancy and reduce the risk of targeted attack. Key architectural considerations:

- **Geographic distribution:** Watchers should be deployed across diverse network locations to prevent localized network partitions from affecting consensus.
- **Infrastructure independence:** Watchers should not share hosting providers, network paths, or administrative access to minimize correlated failures.
- **Scale:** The pool size should match the validator's security requirements. More watchers provide stronger assurance but increase latency for consensus.

### 7.2 Watcher Discovery and Registration

A validator registers watchers through the observation database (`obvs`). Each registration record binds a triple of `(controller_pre, watcher_aid, watched_aid)` with an enabled flag. Watchers may be added, removed, or disabled at any time without affecting the KEL of any watched AID.

### 7.3 Key State Query Flow

The interaction between a validator and its watcher pool follows this sequence:

1. **Query initiation.** A `KeyStateNoticer` issues a key state query (`ksn` request) to witnesses via a `WitnessInquisitor`.
2. **Key state collection.** Responses (KeyStateNotices) from witnesses and watchers are stored in the `knas` and `ksns` databases, indexed by `(watched_aid, reporter_aid)`.
3. **Adjudication.** An `AdjudicationDoer` continuously processes the `Adjudicator`'s message queue, calling `adjudicate()` for each request.
4. **Cue consumption.** Downstream components read cues from the `Adjudicator` and take appropriate action (fetch new KEL entries, raise alerts, etc.).

### 7.4 Async Processing

Adjudication is performed asynchronously via the `AdjudicationDoer`, which extends HIO's `doing.Doer`. On each `recur()` cycle, it calls `performAdjudications()` to drain the message queue. This non-blocking design allows the validator to continue processing other events while adjudication proceeds.

---

## 8. Security Considerations

### 8.1 Eclipse Attacks

An attacker who controls all watchers a validator uses can present a consistent but false view of an AID's key state. Mitigations:

- Use watchers operated by independent parties
- Rotate watchers periodically
- Cross-validate watcher results against direct witness queries

### 8.2 Watcher Compromise

A compromised watcher can report false key state. The adjudication threshold protects against this: as long as fewer than `toad` watchers are compromised, the adjudicator will detect the inconsistency and emit a `keyStateDuplicitous` cue.

### 8.3 Network Partitioning

If a watcher is partitioned from the witness network, it will fall behind and report stale key state. The adjudicator handles this gracefully via the `keyStateLagging` cue, alerting the validator to investigate connectivity.

### 8.4 Watcher Confidentiality

Keeping watcher composition confidential prevents an attacker from targeting the validator's specific watcher set. If the attacker does not know which watchers a validator uses, eclipse and targeted compromise attacks become significantly harder.

---

## 9. Implementation Notes

### 9.1 keripy Reference

The keripy implementation provides the following components:

| Component | Module | Role |
|-----------|--------|------|
| `DiffState` | `watching.py` | Dataclass for key state comparison results |
| `Stateage` / `States` | `watching.py` | Named tuple enumerating the four comparison states |
| `diffState()` | `watching.py` | Function that compares two KeyStateRecords and returns a DiffState |
| `Adjudicator` | `watching.py` | Class that performs key state adjudication with threshold |
| `AdjudicationDoer` | `watching.py` | HIO Doer that drives async adjudication processing |
| `QueryDoer` | `querying.py` | Coordinates key state queries and log retrieval |
| `KeyStateNoticer` | `querying.py` | Issues key state queries and triggers log fetching when updates are detected |

### 9.2 Database Tables

| Table | Key | Purpose |
|-------|-----|---------|
| `obvs` | `(controller_pre, watcher_aid, watched_aid)` | Observation registry: which watchers are monitoring which AIDs |
| `knas` | `(watched_aid, reporter_aid)` | Maps watcher/AID pairs to the SAID of the latest KeyStateNotice |
| `ksns` | `(said,)` | Stores KeyStateNotice records by their SAID |

### 9.3 Cross-References

- **Duplicity detection hierarchy:** See [Watcher Duplicity](watcher-duplicity.md) for the Juror/Jury/Judge model.
- **KEL escrow and duplicity handling:** See `eventing.py` for `escrowLDEvent()`, `processEscrowDuplicitous()`, and `LikelyDuplicitousError`.
- **Witness protocol:** See [KEL Core](kel-core.md) for witness designation, TOAD, and KAWA.
