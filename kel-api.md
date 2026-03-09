# KEL API: Developer Abstractions and Reference

**Version:** 0.1.1-draft
**Status:** Draft
**Part of:** [KEL Specification](kel-specification.md)
**Dependencies:** [KEL Crypto](kel-crypto.md), [KEL Core](kel-core.md), [KEL Engine](kel-engine.md)

---

KERI should NOT be a field manipulation exercise. Developers work with concepts
— keys, thresholds, witnesses, delegation — not raw `{v, t, d, i, s, kt,
k, ...}` field maps.

This document defines concept-level builders, read-only state views, typed
escrow queries, a staged verification pipeline, and reference material
(storage interface, invariants, examples). These abstractions are designed to
be implementable in any language while hiding the wire-format plumbing.

---

## 1. Event Builders

Each builder maps **concepts** to **wire-format fields**. Developers set
meaningful properties; the builder produces a valid serialized event.

### InceptionBuilder

```
InceptionBuilder

  -- Signing --
  .signing_keys([key1, key2, key3])         → field k
      key1..keyN are Verfer qb64 strings

  .signing_threshold(2)                     → field kt
      DEFAULT: ceil(len(signing_keys) / 2)
      Note: the default is a developer convenience, not a protocol
      requirement. High-security contexts may prefer unanimous
      (kt == len(k)); availability-critical systems may use lower
      thresholds.

  -- Pre-rotation --
  .next_keys([nk1, nk2])                   → field n
      Auto-digests keys using Blake3-256    (developers provide keys,
      builder computes digests)             not raw digests

  .next_key_threshold(2)                    → field nt
      DEFAULT: ceil(len(next_keys) / 2)

  -- Witnesses --
  .witnesses([w1, w2, w3])                  → field b
      DEFAULT: [] (no witnesses)

  .witness_threshold(2)                     → field bt
      DEFAULT: ample(len(witnesses))

  -- Configuration --
  .establishment_only()                     → field c += "EO"
  .do_not_delegate()                        → field c += "DND"

  -- Anchoring --
  .anchored_seals([seal1, seal2])           → field a
      Seals are typed (EventSeal, DigestSeal, etc.)

  -- Build --
  .build() → Event
      Validates all constraints, computes version string,
      computes SAID for d and i, returns serialized event.

  -- Type narrowing --
  .non_transferable() → NarrowedInceptionBuilder
      Returns builder WITHOUT .next_keys(), .witnesses(),
      .anchored_seals() — enforces non-transferable constraints
      at the type level.
```

**Method → field mapping:**

| Method | Wire field | Default |
|--------|-----------|---------|
| `signing_keys(keys)` | `k` | REQUIRED |
| `signing_threshold(n)` | `kt` | `ceil(len(k) / 2)` |
| `next_keys(keys)` | `n` (auto-digested) | `[]` |
| `next_key_threshold(n)` | `nt` | `ceil(len(n) / 2)` |
| `witnesses(wits)` | `b` | `[]` |
| `witness_threshold(n)` | `bt` | `ample(len(b))` |
| `establishment_only()` | `c += ["EO"]` | not set |
| `do_not_delegate()` | `c += ["DND"]` | not set |
| `anchored_seals(seals)` | `a` | `[]` |

**Build-time validation:**
- `signing_threshold` >= 1 and <= `len(signing_keys)`
- `next_key_threshold` >= 0 and <= `len(next_keys)`
- `witness_threshold` bounds: 0 if no witnesses, else 1 <= bt <= len(witnesses)
- No duplicate witnesses
- Non-transferable: next_keys, witnesses, anchored_seals must be empty

### RotationBuilder

```
RotationBuilder

  .identifier(prefix)                       → field i
  .signing_keys([new_k1, new_k2])           → field k
  .signing_threshold(n)                     → field kt
  .previous_event(said)                     → field p
  .sequence_number(sn)                      → field s
  .next_keys([future_k1])                   → field n (auto-digested)
  .next_key_threshold(n)                    → field nt
  .cut_witnesses([w_remove])                → field br
  .add_witnesses([w_add])                   → field ba
  .witness_threshold(n)                     → field bt
  .anchored_seals([seal])                   → field a
  .build() → Event

  -- Convenience --
  .from_key_state(state) → RotationBuilder
      Pre-fills: identifier, previous_event (from state.latest_event_said),
      sequence_number (state.sequence_number + 1),
      witnesses (from state for derivation)
```

**Build-time validation:**
- `sequence_number` >= 1
- `previous_event` MUST be provided
- `signing_keys` must satisfy prior pre-rotation commitments (checked against
  KeyState if available)
- Witness derivation rules (cuts ⊂ current, adds ∩ current = ∅, etc.)

### InteractionBuilder

```
InteractionBuilder

  .identifier(prefix)                       → field i
  .previous_event(said)                     → field p
  .sequence_number(sn)                      → field s
  .anchored_seals([seal])                   → field a
  .build() → Event

  .from_key_state(state) → InteractionBuilder
      Pre-fills: identifier, previous_event, sequence_number + 1
```

### DelegatedInceptionBuilder

```
DelegatedInceptionBuilder extends InceptionBuilder

  .delegator(delegator_prefix)              → field di
      REQUIRED — sets ilk to "dip"
```

All InceptionBuilder methods are available. The `delegator()` method is
required and distinguishes `dip` from `icp`.

### DelegatedRotationBuilder

```
DelegatedRotationBuilder extends RotationBuilder

  -- ilk forced to "drt"
  -- Delegation seal validation applied on build
```

### ReceiptBuilder

```
ReceiptBuilder

  .for_event(event) → ReceiptBuilder
      Extracts i, s, d from the event to receipt
  .build() → Receipt
```

### Seal Builders (Typed, Discoverable)

```
EventSeal.of(identifier, sequence_number, digest)    → {i, s, d}
DigestSeal.of(digest)                                → {d}
RootSeal.of(digest)                                  → {rd}
SourceSeal.of(sequence_number, digest)               → {s, d}
LastEstSeal.of(identifier)                           → {i}
BackerSeal.of(backer_prefix, digest)                 → {bi, d}
KindSeal.of(type_version, digest)                    → {t, d}
```

---

## 2. KeyState (Read-Only Conceptual View)

Wraps the cryptic KeyStateRecord/Kever with human-readable properties:

```
KeyState

  -- Identity --
  .identifier                 -- from field 'i': AID prefix string
  .sequence_number            -- from field 's': int (not hex)
  .latest_event_said          -- from field 'd': SAID string
  .prior_event_said           -- from field 'p': SAID string

  -- Signing --
  .signing_keys               -- from field 'k': list of Verfer qb64 strings
  .signing_threshold          -- from field 'kt': Tholder instance

  -- Pre-rotation --
  .next_key_digests           -- from field 'n': list of Diger qb64 strings
  .next_key_threshold         -- from field 'nt': Tholder instance

  -- Witnesses --
  .witnesses                  -- from field 'b': list of AID prefix strings
  .witness_threshold          -- from field 'bt': int

  -- Timestamps --
  .first_seen_ordinal         -- from field 'f': int
  .first_seen_datetime        -- from field 'dt': ISO-8601 string

  -- Delegation --
  .delegator                  -- from field 'di': AID prefix or None

  -- Derived booleans --
  .is_transferable            -- next_key_digests is not empty
  .is_delegated               -- delegator is not None/empty
  .is_establishment_only      -- "EO" in config_traits
  .is_do_not_delegate         -- "DND" in config_traits

  -- Latest establishment event --
  .last_establishment_sn      -- from field 'ee.s': int
  .last_establishment_said    -- from field 'ee.d': SAID string

  -- Builder integration --
  .prepare_rotation() → RotationBuilder
      Returns RotationBuilder pre-filled with:
        identifier, previous_event=latest_event_said,
        sequence_number=sequence_number+1,
        current witnesses for derivation

  .prepare_interaction() → InteractionBuilder
      Returns InteractionBuilder pre-filled with:
        identifier, previous_event=latest_event_said,
        sequence_number=sequence_number+1
```

---

## 3. Escrow Query Model

Typed escrow reasons replace cryptic database table names:

```
EscrowReason (enum)
  PARTIAL_SIGNATURES          -- sigs below signing threshold (PSE)
  PARTIAL_WITNESSES           -- witness sigs below TOAD (PWE)
  OUT_OF_ORDER                -- prior event not yet in KEL (OOE)
  LIKELY_DUPLICITOUS          -- different SAID at same sn (LDE)
  PENDING_DELEGATION          -- delegator seal not found (PDE)
  DELEGABLE                   -- local delegation awaiting approval
  MISFIT_SOURCE               -- remote source for local-owned event
```

```
PendingEvent
  .event                      -- the escrowed event (serialized)
  .reason                     -- EscrowReason
  .escrowed_at                -- timestamp when escrowed
  .signatures_collected       -- count of valid sigs so far
  .signatures_needed          -- total required by threshold
  .witnesses_collected        -- count of valid witness sigs so far
  .witnesses_needed           -- total required by TOAD
  .is_expired                 -- timeout elapsed?
```

**Query interface:**

```
escrows.pending_for(identifier) → list[PendingEvent]
    Returns all escrowed events for the given AID

escrows.pending_by_reason(reason) → list[PendingEvent]
    Returns all escrowed events with the given reason

escrows.is_pending(identifier, sequence_number) → bool
    True if any event is escrowed at (identifier, sn)
```

---

## 4. Verification Pipeline

Six discrete, independently checkable stages. Each stage returns one of:
- **Accepted** — stage passed, proceed to next
- **Escrowed(reason)** — missing dependency, escrow and retry later
- **Rejected(errors)** — invalid, discard with error details

```
VerificationPipeline

  Stage 1: STRUCTURAL (event format)
    - Version string valid and parseable
    - Field set matches ilk schema (correct fields, correct order)
    - No extra fields (strict mode)
    - SAID in 'd' field matches recomputed digest
    - For inception: prefix in 'i' field matches recomputed SAID

  Stage 2: SEQUENCE (ordering)
    - sn == 0 for inception events
    - sn == previous sn + 1 for normal events
    - sn > last_establishment_sn for recovery rotations
    - Prior SAID ('p') matches current state's latest event SAID
    - estOnly check: reject ixn if EO trait is set

  Stage 3: KEY STATE (constraints)
    - Signing threshold valid: 1 <= kt <= len(k)
    - Next threshold valid: 0 <= nt <= len(n)
    - Witness list: no duplicates
    - Witness derivation: cuts ⊂ existing, adds ∩ existing = ∅
    - TOAD bounds: 0 if no wits, else 1 <= bt <= len(wits)
    - For rotation: new keys match prior pre-rotation commitments

  Stage 4: SIGNATURES (verification)
    4a: Controller signatures
        - Verify each siger against event serialization
        - Check threshold satisfaction
        → If not met: Escrowed(PARTIAL_SIGNATURES)

    4b: Pre-rotation ondex verification (rotation only)
        - Verify each signer's public key digests to match
          the committed next-key digest at their ondex position

    4c: Witness signatures
        - Verify each witness signature
        - Check TOAD satisfaction
        → If not met: Escrowed(PARTIAL_WITNESSES)

    4d: Misfit source check
        - Verify event source (local/remote) matches expectation
        → If misfit: Escrowed(MISFIT_SOURCE)

  Stage 5: DELEGATION (authorization)
    - For dip/drt events only
    - Delegator's KEL contains anchoring EventSeal
      matching (delegate_prefix, delegate_sn, delegate_said)
    - Delegator identifier is not DND
    → If seal not found: Escrowed(PENDING_DELEGATION)

  Stage 6: FINALIZE (commit)
    - Log event to persistent storage
    - Record signatures (controller + witness)
    - Assign first-seen ordinal (fn)
    - Update KeyState (Kever)
    - Generate cues (receipt, notice, witness)
    → Accepted
```

---

## 5. SignedEvent Composition

Events are built then signed in two explicit steps:

```
-- Build then sign --
event = InceptionBuilder()
    .signing_keys([k1.qb64, k2.qb64])
    .next_keys([n1.qb64, n2.qb64])
    .witnesses([w1, w2, w3])
    .build()

signed = event.sign_with([signer1, signer2])
    -- Each signer produces a Siger with the correct index
    -- Returns SignedEvent: (event, [siger1, siger2])
```

```
-- From key state (fluent chain) --
signed = key_state
    .prepare_rotation()
    .signing_keys([new_k1.qb64])
    .next_keys([new_n1.qb64])
    .cut_witnesses([old_w1])
    .add_witnesses([new_w4])
    .build()
    .sign_with([new_signer])
```

---

## 6. End-to-End Developer Workflow

```
-- 1. Create identity --
inception = InceptionBuilder()
    .signing_keys([my_key.qb64])
    .next_keys([my_next_key.qb64])
    .witnesses([w1, w2, w3])
    .build()
    .sign_with([my_signer])

state = kevery.process(inception)       -- returns KeyState
-- state.identifier = "EABC..."
-- state.sequence_number = 0
-- state.is_transferable = true

-- 2. Rotate keys --
rotation = state.prepare_rotation()
    .signing_keys([new_key.qb64])
    .next_keys([future_key.qb64])
    .cut_witnesses([w1])
    .add_witnesses([w4])
    .build()
    .sign_with([new_signer])

state = kevery.process(rotation)
-- state.sequence_number = 1
-- state.signing_keys = [new_key.qb64]
-- state.witnesses = [w2, w3, w4]

-- 3. Anchor external data --
interaction = state.prepare_interaction()
    .anchored_seals([
        EventSeal.of(other_aid, sn=5, said=other_said),
        DigestSeal.of(document_hash)
    ])
    .build()
    .sign_with([new_signer])

state = kevery.process(interaction)
-- state.sequence_number = 2
-- Key state unchanged (interaction doesn't change keys)

-- 4. Create delegated identifier --
delegated = DelegatedInceptionBuilder()
    .delegator(my_aid)
    .signing_keys([delegate_key.qb64])
    .next_keys([delegate_next.qb64])
    .build()
    .sign_with([delegate_signer])

-- Delegator must also anchor the approval seal:
approval = state.prepare_interaction()
    .anchored_seals([
        EventSeal.of(delegated.identifier, sn=0, said=delegated.said)
    ])
    .build()
    .sign_with([new_signer])

-- 5. Check pending events --
for pending in escrows.pending_for(my_aid):
    match pending.reason:
        case PARTIAL_SIGNATURES:
            print(f"Need {pending.signatures_needed - pending.signatures_collected} more sigs")
        case PARTIAL_WITNESSES:
            print(f"Need {pending.witnesses_needed - pending.witnesses_collected} more witness receipts")
        case OUT_OF_ORDER:
            print(f"Missing prior event before sn={pending.event.sn}")
        case PENDING_DELEGATION:
            print(f"Waiting for delegator seal")
```

---

## Appendix A: Storage Interface

The KEL requires persistent storage. This appendix defines the abstract
storage interface, independent of any specific database technology.

### A.1 EventDatabase Interface

```
EventDatabase

  -- Event storage --
  put_event(prefix, said, serialized_event)
      Store event keyed by (prefix, SAID). Idempotent.

  get_event(prefix, said) → serialized_event or None
      Retrieve event by (prefix, SAID).

  -- KEL sequence index --
  add_kel_entry(prefix, sn, said)
      Add event SAID to KEL at sequence number. Supports duplicates
      at same sn (for duplicity tracking).

  get_kel_entry(prefix, sn) → list[said]
      Get all event SAIDs at sequence number for prefix.

  -- First-seen event log --
  append_fel(prefix, said) → fn
      Append to first-seen log. Returns assigned fn.
      Non-idempotent: fn assigned only once per event.

  get_fel_entry(prefix, fn) → said
      Get event SAID by first-seen ordinal.

  -- Signature storage --
  put_sigs(prefix, said, sigers)
      Store controller signatures. Idempotent (additive).

  get_sigs(prefix, said) → list[siger]
      Get all controller signatures for event.

  put_wigs(prefix, said, wigers)
      Store witness signatures. Idempotent (additive).

  get_wigs(prefix, said) → list[siger]
      Get all witness signatures for event.

  -- Timestamp storage --
  put_datetime(prefix, said, datetime)
      Store first-seen datetime. Idempotent (first write wins).

  get_datetime(prefix, said) → datetime or None

  -- Key state cache --
  put_state(prefix, key_state_record)
      Store/update key state snapshot.

  get_state(prefix) → KeyStateRecord or None

  -- First-seen ordinal storage --
  put_fn(prefix, said, fn)
      Store fn for event.

  get_fn(prefix, said) → fn or None
```

### A.2 Escrow Storage

```
EscrowStore

  -- Per escrow type --
  add(escrow_type, prefix, sn, said)
      Add event to escrow. Supports duplicates at same (prefix, sn).

  remove(escrow_type, prefix, sn, said)
      Remove specific event from escrow.

  iterate(escrow_type) → iterator[(prefix, sn, said)]
      Iterate all entries in escrow type (for periodic processing).

  -- Source tracking --
  put_source(prefix, said, seal_info)
      Store delegation seal info. Non-idempotent (pin/replace).

  get_source(prefix, said) → seal_info or None
```

### A.3 Receipt Storage

```
ReceiptStore

  put_nontrans_receipt(prefix, said, receiptor_prefix, cigar)
      Store non-transferable receipt.

  put_trans_receipt(prefix, said, receiptor_prefix, receiptor_sn,
                    receiptor_said, siger)
      Store transferable receipt (quadruple).

  get_receipts(prefix, said) → ReceiptSet
      Get all receipts for an event.
```

### A.4 Implementation Note

The reference implementation (keripy) uses LMDB with specific sub-database
naming:

| Abstract operation | keripy sub-database |
|-------------------|---------------------|
| Event storage | `evts.` (SerderSuber) |
| KEL index | `kels.` (OnIoDupSuber) |
| FEL log | `fels.` (OnSuber) |
| Controller sigs | `sigs.` (CesrIoSetSuber) |
| Witness sigs | `wigs.` (CesrIoSetSuber) |
| Timestamps | `dtss.` (CesrSuber) |
| Key state | `states` (Komer) |
| First-seen ordinals | `fons.` (CesrSuber) |
| Event source | `esrs.` (Komer) |
| Delegation seals | `aess.` (CatCesrSuber) |

---

## Appendix B: External Integration Points

The KEL provides integration points for external protocols through seals and
key state queries.

### B.1 Seal Anchoring (KEL → External)

External protocols anchor into the KEL by placing seals in event `a` fields:

```
-- ACDC credential issuance anchored in KEL --
interaction.anchored_seals([
    DigestSeal.of(credential_said)
])

-- TEL registry event anchored in KEL --
interaction.anchored_seals([
    EventSeal.of(registry_prefix, registry_sn, registry_said)
])
```

The KEL stores the seal but does not interpret it. Validators of the external
protocol must independently verify the seal references the expected external
event.

### B.2 Key State Query (External → KEL)

External protocols query the KEL's key state to verify signatures:

```
-- Verify a signature made by an AID --
state = get_key_state(signer_aid)
verfers = state.signing_keys
tholder = state.signing_threshold

-- Check signature at specific event --
state_at_event = get_key_state_at(signer_aid, event_sn)
```

### B.3 Delegation Chain (Hierarchical Trust)

Delegation creates hierarchical trust relationships:

```
Root AID (self-certifying)
  └── Delegated AID 1 (authorized by root)
       └── Delegated AID 1.1 (authorized by AID 1)
```

Each level's key state is independently verifiable by replaying its KEL, but
the delegation seal in the parent's KEL must also be verified.

---

## Appendix C: Invariants

These invariants MUST hold for a valid KEL at all times.

### C.1 Structural Invariants

1. **SAID integrity:** For every event in the KEL, the `d` field MUST equal
   the Blake3-256 SAID of the event serialization.

2. **Digest chain:** For every non-inception event at sn > 0, the `p` field
   MUST equal the `d` field of the event at sn - 1.

3. **Inception uniqueness:** There MUST be exactly one inception event
   (sn = 0) per AID prefix.

4. **Sequence monotonicity:** Events MUST be logged with non-decreasing
   sequence numbers. A gap is permitted only during recovery.

5. **First-seen monotonicity:** First-seen ordinals (`fn`) MUST be strictly
   increasing per AID prefix, with no gaps.

### C.2 Key State Invariants

6. **Threshold bounds:** At every establishment event:
   `1 <= signing_threshold.size <= len(signing_keys)`.

7. **Pre-rotation commitment:** Every rotation event's signing keys MUST
   satisfy the pre-rotation commitment from the prior establishment event.

8. **Non-transferable permanence:** Once an identifier is created as
   non-transferable (empty `n` field at inception), it MUST NOT have any
   subsequent events.

9. **Configuration permanence:** The `EO` and `DND` traits, once set at
   inception, MUST NOT be removed by rotation.

### C.3 Witness Invariants

10. **No duplicate witnesses:** The witness list MUST NOT contain duplicate
    prefixes at any point.

11. **TOAD bounds:** If the witness list is non-empty:
    `1 <= TOAD <= len(witnesses)`. If empty: `TOAD == 0`.

12. **Witness derivation consistency:** After rotation:
    `new_witnesses = (old_witnesses - cuts) ∪ adds`, with no duplicates and
    no overlap between cuts/adds.

### C.4 Delegation Invariants

13. **Seal existence:** Every `dip` or `drt` event MUST have a corresponding
    EventSeal in the delegator's KEL.

14. **DND enforcement:** No identifier with the `DND` trait may serve as a
    delegator.

### C.5 Signature Invariants

15. **Threshold satisfaction:** Every accepted event MUST have verified
    signatures satisfying the signing threshold.

16. **TOAD satisfaction:** Every accepted establishment event MUST have
    verified witness signatures satisfying the TOAD (for events with
    witnesses).

---

## Appendix D: Reference Examples

### D.1 Simple Inception and Rotation

```json
// Inception event (icp)
{
  "v": "KERI10JSON000120_",
  "t": "icp",
  "d": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
  "i": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
  "s": "0",
  "kt": "1",
  "k": ["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"],
  "nt": "1",
  "n": ["EMQQx1qz-HCuHMsCHJK5bnkAt-oq6jGpivdPazusJvas"],
  "bt": "2",
  "b": [
    "BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8I",
    "BFOWfJGBBJDhsRxU1gwajMGnqTstbMwJ20YH21JFXHM4",
    "BBilc4-L3tFUnfM_wJr636TZGwB3BbRPSTkGDPMECFaXg"
  ],
  "c": [],
  "a": []
}
```

**Observations:**
- `d` and `i` are identical (both are SAIDs of the inception event)
- `s` is `"0"` (inception is always sn 0)
- Single signing key with threshold 1
- One next key digest for pre-rotation
- Three witnesses with TOAD of 2

```json
// Rotation event (rot)
{
  "v": "KERI10JSON000160_",
  "t": "rot",
  "d": "ECJt66bVjJO-WP_GBgGrrkCc3GOQPK8Ll_pHWPJZiQeU",
  "i": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
  "s": "1",
  "p": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
  "kt": "1",
  "k": ["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],
  "nt": "1",
  "n": ["ENJPEMECFaXg7FXHM4-L3tFWJr636TZGwB3BilcUnfM_"],
  "bt": "2",
  "br": ["BBilc4-L3tFUnfM_wJr636TZGwB3BbRPSTkGDPMECFaXg"],
  "ba": ["BIKKuvBwpmDVA4Ds-wpbuoM77JRCagfyA2bMDnIF5GBc"],
  "a": []
}
```

**Observations:**
- `p` matches the inception's `d` (digest chain)
- `s` is `"1"` (next after inception)
- New signing key; old key is no longer valid
- Removed one witness (`br`), added one (`ba`)

### D.2 Interaction with Seals

```json
// Interaction event (ixn) anchoring external data
{
  "v": "KERI10JSON000098_",
  "t": "ixn",
  "d": "EHqG9Z3At4tJicfkE_KDCf1gRo8JjQTMf1hVIk01xPeA",
  "i": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
  "s": "2",
  "p": "ECJt66bVjJO-WP_GBgGrrkCc3GOQPK8Ll_pHWPJZiQeU",
  "a": [
    {
      "i": "EFnYGvF_ENKJ7fBLsFkVK0BuCaRiqbMgPRLXrbPMyY38",
      "s": "0",
      "d": "EE2Qcmhm_PsPBmBwiXK4k2eF-McGxOh3ei8epq7eIK5M"
    }
  ]
}
```

**Observations:**
- Key state unchanged (same signing key as after rotation)
- Single EventSeal anchoring a reference to another AID's event
- `p` links to the rotation event's SAID

### D.3 Delegated Inception

```json
// Delegated inception (dip)
{
  "v": "KERI10JSON000154_",
  "t": "dip",
  "d": "EKzN6x4KYp3zMiF6S14SgAPSJMm0JJBVJfkjJfhfCBqo",
  "i": "EKzN6x4KYp3zMiF6S14SgAPSJMm0JJBVJfkjJfhfCBqo",
  "s": "0",
  "kt": "1",
  "k": ["DAUDqkmn-hqlQKD8W-FAEa5JUvJC0MKbcV3MF3uiGDMo"],
  "nt": "1",
  "n": ["EE4CsU5wSne5yDX7Q4E8Kl5iSLJT7TJdj0HnXBV4TWnk"],
  "bt": "0",
  "b": [],
  "c": [],
  "a": [],
  "di": "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo"
}
```

**Observations:**
- `t` is `"dip"` (delegated inception)
- `di` field identifies the delegator
- The delegator MUST anchor `EventSeal.of("EKzN6...", "0", "EKzN6...")` in
  its own KEL

---

## Appendix E: Concept Dependency Matrix

This matrix shows which concepts each layer introduces and depends on.

| Concept | Introduced in | Depends on |
|---------|--------------|------------|
| Verfer, Diger, Prefixer | Crypto | CESR spec |
| Number, Tholder | Crypto | CESR spec |
| Siger, Cigar | Crypto | CESR spec |
| SAID computation | Crypto | Diger, serialization |
| Signature verification | Crypto | Verfer, Siger |
| Threshold satisfaction | Crypto | Tholder, signature verification |
| Pre-rotation commitment | Crypto | Diger, Siger.ondex |
| Event field schemas | Core | Crypto primitives |
| Seal types | Core | Prefixer, Diger, Number |
| Digest chain | Core | SAID, Diger |
| Kever (key state) | Core | Event schemas, threshold |
| KeyStateRecord | Core | Kever fields |
| State transitions | Core | Event schemas, Kever |
| Recovery | Core | Sequence validation, digest chain |
| Witness model | Core | Non-transferable Prefixer |
| TOAD | Core | Ample formula, Number |
| Receipt | Core | Cigar, Siger, witness list |
| Delegation | Core | EventSeal, Kever, witness model |
| Superseding rules | Core | Recovery, delegation |
| Kevery (processing) | Engine | Kever, all escrow triggers |
| First-seen ordering | Engine | Event logging |
| Duplicity detection | Engine | Sequence validation |
| Cue system | Engine | Processing modes |
| Escrow types (7) | Engine | All Crypto+Core triggers |
| Escrow lifecycle | Engine | Timeouts, reprocessing |
| Event builders | API | Event schemas (Core) |
| KeyState view | API | Kever/KeyStateRecord (Core) |
| EscrowReason enum | API | Escrow types (Engine) |
| VerificationPipeline | API | All verification stages (Crypto+Core+Engine) |
| SignedEvent | API | Builders + Siger (Crypto) |

### Developer Persona Map

| Persona | Start With |
|---------|-----------|
| **Controller dev** (creating AIDs, signing) | Crypto + Core + API |
| **Verifier / infrastructure dev** (replaying KELs, running witnesses) | Crypto + Core + Engine |
| **Integration dev** (connecting ACDC/TEL) | Crypto + Core (via `KeyStateProvider` interface) |
| **Full-stack / framework** | All specs |

---

*End of KEL API Specification v0.1.0-draft*
