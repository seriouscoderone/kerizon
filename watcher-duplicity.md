# Watcher Duplicity: Detection Hierarchy

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Specification of the Juror, Jury, and Judge hierarchy for detecting, collecting, and evaluating duplicity evidence in KERI, and the trust rules validators apply based on that evidence.
**Normative basis:** [KERI Specification](https://trustoverip.github.io/kswg-keri-specification/)
**Cross-checked against:** keripy reference implementation (`watching.py`, `eventing.py`)

---

## 1. Purpose and Scope

This document specifies the duplicity detection hierarchy that validators use to determine whether an AID's key event log has been forked. The hierarchy consists of three roles:

- **Juror** — a watcher that records and provides evidence of duplicity
- **Jury** — a pool of Jurors operating as a collective duplicity detection service
- **Judge** — evaluates duplicity evidence (or its absence) and aids validators in making trust decisions

Together, these roles form the evidentiary basis for the fundamental KERI trust rule: trust in the absence of evidence of duplicity, and do not trust when evidence of duplicity exists.

This spec builds on the Watcher Core Protocol. See [Watcher Core](watcher-core.md) for the DiffState model, Adjudicator, and key state comparison mechanics.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Duplicity** | The provable existence of two or more properly signed and/or witnessed versions of the same event (same AID prefix and sequence number, different SAIDs). |
| **Duplicitous Event** | An event that has the same `(pre, sn)` as an already-accepted event but a different digest. Both versions must be properly signed to constitute duplicity (as opposed to a simple invalid event). |
| **Juror** | A watcher that records and provides evidence of duplicity to other watchers and validators. |
| **Jury** | A highly available, fault-tolerant pool of Jurors providing collective duplicity detection. |
| **Judge** | A component that evaluates key events based on duplicity evidence from Juries and aids validators in trust decisions. |
| **Reconciliation** | The process of resolving duplicity, typically through a recovery rotation that supersedes the duplicitous event. |
| **Likely Duplicitous Escrow (LDE)** | An escrow for events that are potentially duplicitous but whose status cannot yet be conclusively determined. |
| **Dead Exploit** | A key compromise that is detected after the fact via the existence of prior copies of the proper KERL, enabling identification of forged events. |
| **Ambient Verifiability** | The property that widespread KEL distribution across watchers makes isolation attacks prohibitively expensive. |

---

## 3. Duplicity Definition

Duplicity in KERI has a precise, provable definition:

> **Duplicity exists when two or more versions of the same event (same AID prefix and sequence number) are both properly signed according to the key state at that sequence number.**

This is distinct from:

- **Invalid events:** An event with insufficient or incorrect signatures is simply rejected, not duplicitous.
- **Duplicate events:** An event with the same `(pre, sn)` AND the same SAID is a harmless duplicate (identical content resent), not a duplicitous event.
- **Out-of-order events:** An event with a sequence number beyond the next expected is escrowed as out-of-order, not duplicitous.

The critical property of duplicity is that it requires the controller's private keys to produce. A properly signed alternative version of an event is proof that either:

1. The controller intentionally signed two different versions (malicious behavior), or
2. The controller's keys have been compromised and an attacker produced the alternative version.

In either case, the validator must treat the AID as untrustworthy until the duplicity is reconciled.

### 3.1 Detection at the Event Level

In the keripy reference implementation, duplicity detection occurs in the `Kevery.processEvent()` method. When an incoming event matches an existing `(pre, sn)` but has a different SAID:

- For inception events (`icp`, `dip`): the new event is compared against the existing establishment event. If SAIDs differ, it is escrowed as likely duplicitous via `escrowLDEvent()`.
- For interaction and rotation events (`ixn`, `rot`, `drt`): the digest stored in the `kels` database is compared. If the incoming SAID does not match, the event is escrowed as likely duplicitous.

The `LikelyDuplicitousError` exception signals this condition, and the event is placed in the `ldes` (Likely Duplicitous Event) escrow for later processing.

### 3.2 Detection at the Key State Level

At the key state level, duplicity is detected by the Adjudicator (see [Watcher Core](watcher-core.md), section 6). When comparing DiffState records:

- **Same sequence number, different digest:** Direct evidence of duplicity. The watcher and local node have accepted different versions of the same event.
- **Multiple ahead watchers with different digests:** Indirect evidence. The watchers themselves have seen different versions, indicating a fork in the KEL.

---

## 4. Juror Role

A Juror is a specialized watcher that focuses on collecting and preserving evidence of duplicity.

### 4.1 Evidence Collection

A Juror collects duplicity evidence by:

1. **Maintaining first-seen records.** Like all watchers, a Juror applies the first-seen policy. The first properly verified event at each `(pre, sn)` becomes the Juror's accepted version.

2. **Preserving duplicitous variants.** When a second properly signed event arrives at the same `(pre, sn)` with a different SAID, the Juror retains both versions. The combination of two properly signed variants at the same sequence number constitutes verifiable proof of duplicity.

3. **Recording provenance.** The Juror records when and from where each variant was received, establishing a timeline of the duplicitous event's propagation.

The evidence a Juror maintains is self-verifying: any third party can independently confirm that both event variants are properly signed under the key state at that sequence number. No trust in the Juror's honesty is required to verify the evidence itself.

### 4.2 Evidence Sharing

Jurors share duplicity evidence through two mechanisms:

1. **On request.** When queried by a validator or another Juror, a Juror provides its collected duplicity evidence for the requested AID.

2. **Proactive dissemination.** A Juror MAY proactively share evidence with other Jurors and validators to accelerate detection across the network. Because duplicity evidence is self-verifying, sharing it widely increases the security of the entire ecosystem.

Jurors have a strong incentive to share evidence broadly. Withholding evidence benefits only the duplicitous controller. Honest participants — controllers, validators, and infrastructure operators — all benefit from rapid dissemination of duplicity evidence.

---

## 5. Jury Architecture

A Jury is a pool of Jurors that collectively provides a duplicity detection service.

### 5.1 Pool Composition

A Jury SHOULD consist of multiple independent Jurors to provide:

- **Redundancy:** If some Jurors are unavailable, the remaining Jurors continue to detect and report duplicity.
- **Coverage:** Different Jurors may be connected to different parts of the network and see different evidence. A pool aggregates coverage.
- **Resistance to suppression:** An attacker who compromises one Juror cannot suppress evidence held by the other Jurors.

The composition of a Jury is determined by the validator. Different validators may use different Juries, and a single Juror may participate in multiple Juries.

### 5.2 Fault Tolerance

A Jury tolerates faults through redundancy and self-verifying evidence:

- **Crash faults:** A Juror that goes offline does not affect the evidence held by other Jurors. The Jury continues to function with reduced coverage.
- **Byzantine faults:** A compromised Juror that suppresses evidence cannot prevent other Jurors from independently detecting and reporting the same duplicity. A compromised Juror that fabricates evidence is detectable because duplicity evidence must be properly signed by the controller's keys — a Juror cannot forge this.
- **Partition faults:** Jurors on different sides of a network partition will independently detect duplicity if the attacker attempts to present different KEL versions to different network segments.

The key property is that duplicity evidence is cryptographically self-verifying. The Jury's reliability depends on coverage (at least one honest Juror seeing the evidence), not on trusting any individual Juror.

---

## 6. Judge Role

A Judge evaluates key events based on duplicity evidence (or its absence) from Juries and aids the validator in making trust decisions.

### 6.1 Evidence Evaluation

A Judge queries its configured Jury (or Juries) for duplicity evidence related to a specific AID. The evaluation produces one of two outcomes:

- **No evidence of duplicity:** The Jury has not detected any forked events for this AID. The Judge advises the validator that the AID may be trusted.
- **Evidence of duplicity exists:** The Jury has detected one or more duplicitous event pairs. The Judge advises the validator that the AID MUST NOT be trusted until the duplicity is reconciled.

The Judge does not need to trust the Jury's assertions. Because duplicity evidence consists of two properly signed event variants, the Judge independently verifies the evidence by checking the signatures against the relevant key state.

### 6.2 Trust Decisions

The fundamental trust rule that a Judge enforces:

> **An honest validator MUST trust when there is no evidence of duplicity and MUST NOT trust when there is any evidence of duplicity, unless and until the duplicity has been reconciled.**

This rule is binary and immediate:

- **Trust is the default** in the absence of counter-evidence. KERI does not require positive proof of honesty — it requires only the absence of evidence of dishonesty.
- **Distrust is immediate** upon receipt of verified duplicity evidence. There is no grace period, no threshold of severity, and no consideration of the controller's history. A single verified duplicitous event pair is sufficient to revoke trust.
- **Trust may be restored** only through reconciliation (see section 6.3).

### 6.3 Reconciliation Mechanisms

KERI provides mechanisms for reconciling duplicity, primarily through key rotation:

1. **Recovery rotation.** The controller performs a rotation event that supersedes the duplicitous sequence number. The new rotation establishes a new key state and implicitly invalidates the duplicitous fork. This works because pre-rotation commitments (next key digests) in prior establishment events bind the legitimate rotation path.

2. **Delegation revocation.** For delegated AIDs, the delegator can revoke the delegation, effectively abandoning the compromised AID.

3. **Abandonment.** The controller can abandon the compromised AID and establish a new one, migrating relationships to the new identifier.

Reconciliation requires controller action. The validator and Judge cannot reconcile duplicity unilaterally — they can only observe that reconciliation has occurred and restore trust accordingly.

---

## 7. Ambient Verifiability and Dead Exploit Defense

### 7.1 Ambient Verifiability

Ambient verifiability is the property that arises from widespread KEL distribution across the watcher network:

> **When KELs are widely distributed across independent watchers, an attacker cannot present a forged KEL without it being detected by at least some watchers who hold the legitimate version.**

The more watchers that hold copies of a KEL, the harder it becomes for an attacker to:

- **Isolate a validator.** The attacker would need to compromise or partition all watchers the validator uses.
- **Suppress evidence.** Even if the attacker controls some watchers, independent watchers will detect and report the discrepancy.
- **Rewrite history.** Prior copies of the legitimate KEL serve as evidence against any forged alternative.

Ambient verifiability is a statistical property: it grows stronger with more independent watchers and more widespread distribution. It does not require a global consensus mechanism — it emerges naturally from the distributed nature of the watcher network.

### 7.2 Dead Exploit Defense

A "dead exploit" is the scenario where an attacker compromises ALL current private keys of a controller and uses them to forge an alternative KEL. KERI defends against this through the combination of:

1. **Pre-rotation.** Even with all current keys compromised, the attacker cannot determine the next rotation keys (they are committed only as digests in prior establishment events). The legitimate controller can perform a recovery rotation using the pre-committed next keys.

2. **Prior KEL copies.** Watchers that received the legitimate KEL before the compromise retain copies. When the attacker presents a forged KEL, the discrepancy between the forged version and the prior copies held by watchers constitutes verifiable duplicity evidence.

3. **First-seen policy.** Watchers that already accepted the legitimate events at each sequence number will reject the forged alternatives as duplicitous, regardless of the forged events' cryptographic validity.

The term "dead" in "dead exploit" refers to the fact that the exploit is detectable even after the fact — the attacker cannot erase the prior legitimate copies held by watchers. The attack leaves behind evidence that persists indefinitely.

### 7.3 Controller and Validator Incentives

Both controllers and validators benefit from widespread, low-latency watcher networks:

- **Controllers** benefit because widespread distribution of their legitimate KEL makes it harder for an attacker to forge an undetected alternative. The controller has an incentive to ensure their events propagate quickly to as many watchers as possible.
- **Validators** benefit because a larger, more diverse watcher pool provides stronger assurance against eclipse attacks and targeted compromise.

This alignment of incentives naturally drives the growth of the watcher network without requiring a coordination mechanism.

---

## 8. Validator Integration

### 8.1 Using the Hierarchy

A validator integrates the Juror/Jury/Judge hierarchy as follows:

1. **Configure a Jury.** Select a set of Jurors (watchers with duplicity detection capability) and register them as the validator's Jury.

2. **Adjudicate key state.** Use the Adjudicator (see [Watcher Core](watcher-core.md)) to compare key state across the watcher pool. If the Adjudicator emits a `keyStateDuplicitous` cue, escalate to the Judge.

3. **Evaluate duplicity.** When duplicity is suspected, the Judge queries the Jury for evidence. The Judge independently verifies any evidence received.

4. **Apply trust rule.** Based on the Judge's evaluation, the validator either trusts the AID (no evidence of duplicity) or suspends trust (evidence exists) until reconciliation.

### 8.2 Integration with KEL Processing

The keripy reference implementation integrates duplicity handling directly into KEL processing:

| Component | Module | Duplicity Role |
|-----------|--------|----------------|
| `Kevery.processEvent()` | `eventing.py` | Detects likely duplicitous events during ingestion |
| `escrowLDEvent()` | `eventing.py` | Escrows events that may be duplicitous for later evaluation |
| `processEscrowDuplicitous()` | `eventing.py` | Re-evaluates escrowed likely-duplicitous events |
| `duplicity()` | `eventing.py` | Placeholder for duplicity processing logic |
| `Adjudicator.adjudicate()` | `watching.py` | Detects key state duplicity across watcher pool |
| `TimeoutLDE` | `eventing.py` | 3600-second timeout for likely duplicitous escrows |

### 8.3 Escrow Lifecycle

Events suspected of duplicity follow this lifecycle:

1. **Detection.** During `processEvent()`, an incoming event matches an existing `(pre, sn)` but has a different SAID. A `LikelyDuplicitousError` is raised.

2. **Escrow.** The event is placed in the `ldes` (Likely Duplicitous Events) database via `escrowLDEvent()`. Associated signatures and timestamps are stored.

3. **Re-evaluation.** The `processEscrowDuplicitous()` method periodically re-processes escrowed events. If the event can now be validated (e.g., missing dependencies have arrived), it is either accepted or confirmed as duplicitous. If it is still indeterminate, it remains escrowed.

4. **Timeout.** Escrowed events that remain indeterminate for longer than `TimeoutLDE` (3600 seconds) are removed. This prevents unbounded escrow growth.

5. **Resolution.** Events confirmed as duplicitous are logged. Events that turn out to be valid (e.g., they were escrowed due to missing out-of-order dependencies) are processed normally.

Note: during unescrow processing, not all escrows at a given `(pre, sn)` are removed at once because some may be genuinely duplicitous while others are valid. Each escrow is evaluated individually.

---

## 9. Security Considerations

### 9.1 Evidence Integrity

Duplicity evidence is cryptographically self-verifying. Both event variants must be properly signed under the key state at the relevant sequence number. This means:

- A Juror cannot fabricate duplicity evidence (it would require the controller's private keys).
- A Juror cannot tamper with genuine evidence without invalidating the signatures.
- Any party can independently verify the evidence without trusting the Juror.

### 9.2 Evidence Suppression

An attacker may attempt to suppress duplicity evidence by:

- Compromising Jurors and deleting their records
- Partitioning Jurors from the network
- Flooding Jurors with noise to obscure genuine evidence

Mitigations include using large, geographically diverse Jury pools and ensuring Jurors proactively share evidence with each other and with validators.

### 9.3 Timing Attacks

An attacker may attempt to exploit the time window between key compromise and detection. KERI mitigates this through:

- **Pre-rotation:** The legitimate controller can always supersede a forged rotation by using the pre-committed next keys.
- **Delegation time windows:** Delegated rotations that occur too quickly after a prior rotation may be flagged for additional scrutiny to prevent rapid exploitation of compromised delegate keys.

### 9.4 Total Key Compromise

Even in the extreme case of total current key compromise:

- The attacker cannot forge a valid recovery rotation without the pre-committed next keys.
- Prior copies of the legitimate KEL held by watchers provide evidence against any forged alternative.
- The dead exploit defense ensures detection even if the compromise is discovered after the attacker has acted.

---

## 10. Implementation Notes

### 10.1 keripy Reference

The keripy implementation provides duplicity handling at the Kevery level but does not yet implement a formal Juror/Jury/Judge abstraction. The current implementation:

- Detects likely duplicitous events during `processEvent()` and escrows them
- Processes escrowed duplicitous events via `processEscrowDuplicitous()`
- Detects key state duplicity via the `Adjudicator` class
- Contains a placeholder `duplicity()` method for future formal duplicity processing

The Juror/Jury/Judge hierarchy described in this spec represents the target architecture. Implementations may realize these roles as distinct services, as components within a single process, or as logical functions within existing watcher infrastructure.

### 10.2 Cross-References

- **Watcher core protocol:** See [Watcher Core](watcher-core.md) for DiffState, Adjudicator, and watcher pool architecture.
- **KEL event processing:** See [KEL Engine](kel-engine.md) for Kevery event ingestion and escrow mechanics.
- **Key state and rotation:** See [KEL Core](kel-core.md) for key state, pre-rotation, and witness designation.
