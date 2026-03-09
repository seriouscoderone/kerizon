# KEL Core: Events, Key State, Witnessing, and Delegation

**Version:** 0.1.2-draft
**Status:** Draft
**Part of:** [KEL Specification](kel-specification.md)
**Dependencies:** [KEL Crypto](kel-crypto.md) (primitives, signatures, thresholds, SAID)
**Interface exported:** `KeyStateProvider` — given an AID, return current key state

---

This document defines the event types, key state model, witnessing, and
delegation — everything needed to understand "what KERI is" at the protocol
level. It answers: what goes on the wire, what does it mean, and how does
key state change?

---

## 1. Event Type Taxonomy

```
Key Events
├── Establishment Events (change key state)
│   ├── icp  -- Inception: creates identifier
│   ├── rot  -- Rotation: updates keys/witnesses
│   ├── dip  -- Delegated Inception: creates delegated identifier
│   └── drt  -- Delegated Rotation: updates delegated identifier
├── Non-Establishment Events (do not change key state)
│   └── ixn  -- Interaction: anchors data without key change
└── Acknowledgment Events
    └── rct  -- Receipt: witness/validator acknowledgment
```

---

## 2. Field Definitions

All KEL event fields use compact 1-2 character labels for bandwidth efficiency.
These labels are defined in the KERI specification under "field labels for data
structures."

| Field | Name | Type | Description |
|-------|------|------|-------------|
| `v` | Version | string | Version string (computed — see [Crypto](kel-crypto.md) Section 4) |
| `t` | Type | string | Event type / ilk code |
| `d` | Digest | string | SAID of this event (computed — Blake3-256) |
| `i` | Identifier | string | AID prefix (for icp/dip: computed as SAID) |
| `s` | Sequence | string | Sequence number as hex string (no leading zeros) |
| `p` | Prior | string | SAID of prior event (digest chain link) |
| `kt` | Key threshold | string or list | Signing threshold (sith) |
| `k` | Keys | list[string] | Current signing keys (Verfer qb64 values) |
| `nt` | Next threshold | string or list | Next rotation threshold (nsith) |
| `n` | Next digests | list[string] | Next key digests (Diger qb64 values) |
| `bt` | Backer threshold | string | Witness threshold (TOAD) as hex string |
| `b` | Backers | list[string] | Witness AID prefixes |
| `br` | Backer removes | list[string] | Witnesses removed in this rotation |
| `ba` | Backer adds | list[string] | Witnesses added in this rotation |
| `c` | Config | list[string] | Configuration traits (e.g., `"EO"`, `"DND"`) |
| `a` | Anchors | list[dict] | Seal list (opaque typed references) |
| `di` | Delegator | string | Delegator AID prefix (delegated events only) |

**KEL vs ACDC field overlap:** Fields `v`, `t`, `d`, `i`, `s`, `a` appear in
both KEL and ACDC events with DIFFERENT semantics. For example, `s` is sequence
number in KEL but schema SAID in ACDC. These are separate field sets from
separate specifications.

---

## 3. Event Schemas

Fields MUST appear in the exact order listed below. Required fields MUST be
present. No extra fields are permitted (strict mode).

### 3.1 Inception (icp)

Creates a new non-delegated identifier. The AID prefix (`i`) is derived as a
SAID of the inception event.

**Fields (ordered):** `v`, `t`, `d`, `i`, `s`, `kt`, `k`, `nt`, `n`, `bt`,
`b`, `c`, `a`

**SAID fields:** `d` (Blake3-256), `i` (Blake3-256)

**Constraints:**
- `s` MUST be `"0"`
- `kt` MUST be >= 1 and <= `len(k)`
- `nt` MUST be >= 0 and <= `len(n)`
- If `n` is empty: identifier is non-transferable (no future rotation possible)
- If non-transferable prefix code: `n` MUST be empty, `b` MUST be empty,
  `a` MUST be empty
- `b` MUST contain no duplicates
- `bt`: if `b` is empty then `"0"`, else `"1"` <= `bt` <= `len(b)` (as hex)

### 3.2 Rotation (rot)

Updates keys and/or witnesses for a non-delegated identifier.

**Fields v1.0 (ordered):** `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `k`, `nt`,
`n`, `bt`, `br`, `ba`, `a`

**Fields v2.0 (ordered):** `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `k`, `nt`,
`n`, `bt`, `br`, `ba`, `c`, `a`

**SAID fields:** `d` (Blake3-256)

**Constraints:**
- `s` MUST be >= 1
- `p` MUST equal the SAID of the prior event at `s - 1` (normal case) or a
  valid recovery target
- `kt` MUST be >= 1 and <= `len(k)`
- New signing keys MUST satisfy the pre-rotation commitment from the prior
  establishment event
- `br` (cuts): all MUST be in the current witness list; no duplicates
- `ba` (adds): MUST NOT overlap with current witness list or `br`;
  no duplicates
- Derived witness list: `(current_witnesses - br) ∪ ba`

A rotation event MAY update signing keys only, witness configuration only,
both, or neither (anchoring seals without key/witness changes).

### 3.3 Interaction (ixn)

Anchors data to the KEL without changing key state.

**Fields (ordered):** `v`, `t`, `d`, `i`, `s`, `p`, `a`

**SAID fields:** `d` (Blake3-256)

**Constraints:**
- `s` MUST equal prior event's `s + 1`
- `p` MUST equal prior event's `d` (SAID)
- MUST NOT be used if the identifier has the `EO` (EstOnly) configuration trait

### 3.4 Delegated Inception (dip)

Creates a new delegated identifier bound to a delegator.

**Fields (ordered):** `v`, `t`, `d`, `i`, `s`, `kt`, `k`, `nt`, `n`, `bt`,
`b`, `c`, `a`, `di`

**SAID fields:** `d` (Blake3-256), `i` (Blake3-256)

**Constraints:**
- All inception constraints apply
- `di` MUST be the AID prefix of the delegator
- The delegator's KEL MUST contain an anchoring seal for this event
  (see Section 9)

### 3.5 Delegated Rotation (drt)

Updates keys/witnesses for a delegated identifier. Requires delegator approval.

**Fields v1.0 (ordered):** `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `k`, `nt`,
`n`, `bt`, `br`, `ba`, `a`

**Fields v2.0 (ordered):** `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `k`, `nt`,
`n`, `bt`, `br`, `ba`, `c`, `a`

**SAID fields:** `d` (Blake3-256)

**Constraints:**
- All rotation constraints apply
- The delegator's KEL MUST contain an anchoring seal for this event

### 3.6 Receipt (rct)

Acknowledges an event. Carries no key state changes. Signatures are attached
separately.

**Fields (ordered):** `v`, `t`, `d`, `i`, `s`

**No SAID computation** — the `d` field references the receipted event's SAID,
not a self-computed digest.

**Constraints:**
- `i` identifies the receipted event's AID
- `s` identifies the receipted event's sequence number
- `d` identifies the receipted event's SAID

---

## 4. Autonomic Identifiers (AIDs)

An AID (Autonomic Identifier) is the fundamental unit of identity in KERI — a
self-certifying identifier cryptographically bound to a set of key pairs. Unlike
traditional identifiers (domain names, DIDs backed by ledgers), an AID requires
no trusted third party: the identifier itself is either a public key or a digest
of its own inception event, making the binding between identifier and controlling
keys cryptographically verifiable by anyone.

### 4.1 Two Derivation Modes

AIDs are derived in one of two ways, determined by the CESR code of the `i` field:

**Basic derivation (prefix IS the public key):**
The AID is the CESR-qualified public verification key itself. Used for simple,
non-rotatable identifiers (witnesses, watchers, ephemeral identifiers).

```
AID = Verfer(public_key).qb64    e.g., "BAbcdef..."
```

**Self-addressing derivation (prefix IS the SAID of inception event):**
The AID is a digest of the inception event — binding the identifier to the
full inception content (keys, thresholds, witnesses, configuration). Used for
transferable identifiers that support key rotation.

```
AID = SAID(inception_event)      e.g., "EAbcdef..."
```

The derivation mode is unambiguously determined by the CESR prefix code.

### 4.2 Transferable vs Non-Transferable

This is the most important distinction in KERI identifier design:

| Property | Non-Transferable | Transferable |
|----------|-----------------|--------------|
| **Derivation** | Basic (prefix = public key) | Self-addressing (prefix = SAID of inception) |
| **Key rotation** | Impossible | Supported via pre-rotation commitment |
| **Pre-rotation (`n`)** | MUST be empty | MUST contain next key digests |
| **Witnesses (`b`)** | MUST be empty | MAY designate witnesses |
| **Anchors (`a`)** | MUST be empty | MAY contain seals |
| **Prefix codes** | `B`, `1AAA`, `1AAC`, `1AAI` | `D`, `1AAB`, `1AAD`, `1AAJ`, `E`, `F`, `G`, `H`, `I`, `0D`, `0E`, `0F`, `0G` |
| **Typical use** | Witnesses, watchers, ephemeral | Controllers, issuers, long-lived identifiers |

**Why non-transferable AIDs have these constraints:** Since the AID IS the public
key, there is no inception event structure to anchor witnesses or seals to. The
identifier's entire trust basis is the single key pair — if that key is
compromised, the identifier is permanently compromised with no recovery path.

**Why transferable AIDs use self-addressing:** The SAID derivation binds the
identifier to the inception event, which contains pre-rotation commitments (`n`
field). This enables key rotation: the next set of keys is committed to before
they're needed, so a compromised current key cannot forge a valid rotation
(the attacker doesn't know the pre-committed next keys).

### 4.3 Prefix Code Table

Valid AID prefix codes from `PreCodex` (`coring.py:610-636`):

| Code | Algorithm | Derivation | Transferable |
|------|-----------|------------|-------------|
| `B` | Ed25519 | Basic (public key) | No |
| `D` | Ed25519 | Basic (public key) | Yes |
| `E` | Blake3-256 | Self-addressing (digest) | Yes |
| `F` | Blake2b-256 | Self-addressing (digest) | Yes |
| `G` | Blake2s-256 | Self-addressing (digest) | Yes |
| `H` | SHA3-256 | Self-addressing (digest) | Yes |
| `I` | SHA2-256 | Self-addressing (digest) | Yes |
| `0D` | Blake3-512 | Self-addressing (digest) | Yes |
| `0E` | Blake2b-512 | Self-addressing (digest) | Yes |
| `0F` | SHA3-512 | Self-addressing (digest) | Yes |
| `0G` | SHA2-512 | Self-addressing (digest) | Yes |
| `1AAA` | ECDSA secp256k1 | Basic (public key) | No |
| `1AAB` | ECDSA secp256k1 | Basic (public key) | Yes |
| `1AAC` | Ed448 | Basic (public key) | No |
| `1AAD` | Ed448 | Basic (public key) | Yes |
| `1AAI` | ECDSA secp256r1 | Basic (public key) | No |
| `1AAJ` | ECDSA secp256r1 | Basic (public key) | Yes |

**Default:** `E` (Blake3-256 self-addressing) for transferable identifiers,
`B` (Ed25519 basic) for non-transferable.

### 4.4 Self-Certifying Property

An AID is **self-certifying** because:

1. For basic derivation: the identifier IS the public key — anyone can verify a
   signature directly against the identifier itself, with no lookup required.
2. For self-addressing derivation: the identifier is a digest of the inception
   event, which contains the initial public keys. Anyone with the inception event
   can recompute the digest and verify it matches the identifier, then verify
   signatures against those keys.

This eliminates the need for certificate authorities, trusted registries, or
blockchain lookups. The root of trust is cryptographic, not administrative.

### 4.5 Pre-Rotation and Key Commitment

Transferable AIDs commit to their NEXT key set at inception (and at each
subsequent rotation) via the `n` field, which contains digests of the next
public keys. This pre-rotation commitment means:

- The current controller proves knowledge of future keys without revealing them
- An attacker who compromises current keys cannot forge a valid rotation
  (they don't know the pre-committed next keys)
- Key rotation is verifiable: the new keys must match the prior commitment

See Section 3.2 for rotation mechanics and [Crypto](kel-crypto.md) Section 2
for `Diger` (the digest primitive used for key commitments).

### 4.6 SAID Binding Rules

**SAID binding (all events):** The `d` field is a SAID computed as a Blake3-256
digest of the event serialization (using the SAID computation algorithm from
[Crypto](kel-crypto.md) Section 5).

**Identifier prefix derivation (inception events only):** For `icp` and `dip`
events, the `i` field is ALSO a SAID — computed simultaneously with `d`. This
binds the AID to the inception event content: modifying any field in the
inception event would change both the SAID and the identifier itself.

**Basic prefix derivation (inception events only):** For `icp` events where the
prefix code is in `PreNonDigCodex` (basic derivation), the `i` field is the
first public key in `k` rather than a SAID. The `d` field is still a SAID.

---

## 5. Seal Types and the Opacity Principle

Seals are typed references placed in the `a` (anchors) field of KEL events.
The KEL provides tamper-evident anchoring but is opaque to seal semantics — it
does not interpret what the seal references.

```
EventSeal     { i: prefix, s: sequence_number, d: digest }
              -- References a specific event in another KEL

DigestSeal    { d: digest }
              -- Anchors a digest of arbitrary external data

RootSeal      { rd: digest }
              -- Anchors a Merkle tree root digest

SourceSeal    { s: sequence_number, d: digest }
              -- References an event by sn and digest (AID implied by context)

LastEstSeal   { i: prefix }
              -- References the latest establishment event for an AID

BackerSeal    { bi: backer_prefix, d: digest }
              -- References backer metadata

KindSeal      { t: type_version, d: digest }
              -- Typed/versioned digest seal
```

**Opacity principle:** The KEL does not know or care whether a seal references
a TEL event, an ACDC credential, or any other data structure. The seal's
meaning is determined by the protocol that created it.

---

## 6. Digest Chain Invariant

Every non-inception event MUST contain a `p` field whose value equals the SAID
of its predecessor. This creates an unbroken hash chain from any event back to
inception:

```
icp (sn=0, d=EABC...)
 └─→ ixn (sn=1, p=EABC..., d=EDEF...)
      └─→ rot (sn=2, p=EDEF..., d=EGHI...)
           └─→ ixn (sn=3, p=EGHI..., d=EJKL...)
```

Modifying any event invalidates the SAID chain for all subsequent events.

---

## 7. Witness List Derivation Algorithm

Rotation events do not carry the full witness list. Instead, they carry `br`
(removes) and `ba` (adds), and the new witness list is derived:

```
deriveBacks(current_witnesses, br, ba) → new_witnesses

  1. Verify no duplicates in br
  2. Verify no duplicates in ba
  3. Verify all entries in br exist in current_witnesses
  4. Verify br ∩ ba = ∅  (cannot remove and add same witness)
  5. Verify ba ∩ current_witnesses = ∅  (cannot add existing witness)
  6. new_witnesses = [w for w in current_witnesses if w not in br] + ba
  7. Verify no duplicates in new_witnesses
  8. Return new_witnesses
```

---

## 8. Configuration Traits

Configuration traits are set in the `c` field of establishment events and
constrain identifier behavior.

| Trait | Code | Effect | Scope |
|-------|------|--------|-------|
| Establishment Only | `EO` | Only establishment events allowed; interaction events (`ixn`) are rejected | Set in inception, permanent, identifier-scoped |
| Do Not Delegate | `DND` | This identifier cannot serve as a delegator | Set in inception, permanent |
| Registrar Backers | `RB` | Registrar backer info provided in seal | Establishment events |
| No Backers | `NB` | Disallow any registrar backers (deprecated, use `NRB`) | Establishment events |
| No Registrar Backers | `NRB` | Disallow registrar backers | Establishment events |
| Delegate Is Delegator | `DID` | Treat delegate AIDs same as delegator | Set in inception |

**EO trait scope clarification:** The EO trait is identifier-scoped: it prevents
the controlled identifier from creating `ixn` events. Validators still accept
interaction events from OTHER identifiers. Anchoring seals that reference
EO-controlled identifiers is permitted.

---

## 9. Kever: The Key Event Verifier

A Kever is the authoritative representation of an identifier's current key
state. It is created from an inception event and updated by subsequent events.
All verification of events against an identifier goes through its Kever.

```
Kever
  -- Identity --
  .prefixer              -- Prefixer: AID prefix
  .transferable          -- bool: true if next key digests are non-empty

  -- Sequence tracking --
  .sner                  -- Number: sequence number of latest event
  .fner                  -- Number: first-seen ordinal of latest event
  .serder                -- SerderKERI: latest event
  .ilk                   -- string: latest event type
  .version               -- Versionage: protocol version

  -- Signing keys --
  .verfers               -- list[Verfer]: current signing key instances
  .tholder               -- Tholder: current signing threshold

  -- Pre-rotation --
  .ndigers               -- list[Diger]: next key digests (pre-rotation commitment)
  .ntholder              -- Tholder: next rotation threshold

  -- Witnesses --
  .wits                  -- list[string]: current witness AID prefixes
  .toader                -- Number: witness threshold (TOAD)
  .cuts                  -- list[string]: witnesses removed in latest est event
  .adds                  -- list[string]: witnesses added in latest est event

  -- Delegation --
  .delegated             -- bool: true if this is a delegated identifier
  .delpre                -- string or None: delegator prefix

  -- Configuration --
  .estOnly               -- bool: EO trait active
  .doNotDelegate         -- bool: DND trait active

  -- Last establishment --
  .lastEst               -- (s: int, d: string): sn and SAID of last est event

  -- Timestamps --
  .dater                 -- Dater: first-seen datetime of latest event
```

---

## 10. KeyStateRecord (Serializable Snapshot)

A KeyStateRecord is a serializable snapshot of a Kever's state, suitable for
storage and transmission.

| Field | Type | Source |
|-------|------|--------|
| `vn` | list[int] | Protocol version `[major, minor]` |
| `i` | string | AID prefix qb64 |
| `s` | string | Sequence number (hex) |
| `p` | string | Prior event SAID |
| `d` | string | Latest event SAID |
| `f` | string | First-seen ordinal (hex) |
| `dt` | string | ISO-8601 datetime of state update |
| `et` | string | Latest event type (ilk) |
| `kt` | string or list | Current signing threshold |
| `k` | list[string] | Current signing keys qb64 |
| `nt` | string or list | Next rotation threshold |
| `n` | list[string] | Next key digests qb64 |
| `bt` | string | Witness threshold (hex) |
| `b` | list[string] | Current witness prefixes qb64 |
| `c` | list[string] | Configuration traits |
| `ee` | StateEstEvent | Last establishment event info: `{s, d, br, ba}` |
| `di` | string | Delegator prefix (empty string if not delegated) |

---

## 11. State Transitions

### Inception → Initial State

```
Kever.incept(serder):
  1. Extract keys from serder.k → create Verfer list
  2. Extract signing threshold from serder.kt → create Tholder
  3. Verify: tholder.size <= len(verfers)
  4. Extract next digests from serder.n → create Diger list
  5. Extract next threshold from serder.nt → create Tholder
  6. Extract witnesses from serder.b
  7. Extract TOAD from serder.bt
  8. Verify: sn == 0
  9. Verify: no duplicate witnesses
  10. Verify: TOAD bounds (0 if no wits, else 1 <= toad <= len(wits))
  11. If non-transferable prefix: verify n=[], b=[], a=[]
  12. Parse configuration traits (EO, DND) from serder.c
  13. Set lastEst = (s=0, d=serder.said)
```

### Rotation → Updated State

```
Kever.update(serder) where serder.ilk in {rot, drt}:

  -- Sequence validation --
  1. Verify sn ordering (see Section 12)
  2. Verify prior event digest matches chain

  -- Key validation --
  3. Extract new keys → new Verfer list
  4. Extract new threshold → new Tholder
  5. Verify new keys satisfy prior pre-rotation commitments (ondex check)

  -- Witness validation --
  6. Derive new witness list via deriveBacks(current_wits, br, ba)
  7. Verify new TOAD bounds

  -- Signature validation (delegates to Crypto layer) --
  8. Verify controller signatures meet new threshold
  9. Verify witness signatures meet TOAD

  -- State update (atomic) --
  10. Update: sner, serder, ilk, verfers, tholder
  11. Update: ndigers, ntholder
  12. Update: wits, toader, cuts, adds
  13. Update: lastEst = (s=sn, d=serder.said)
```

### Interaction → Anchoring Only

```
Kever.update(serder) where serder.ilk == ixn:

  1. Verify: not self.estOnly (ixn forbidden with EO trait)
  2. Verify: sn == self.sn + 1
  3. Verify: serder.p == self.serder.said (prior digest matches)
  4. Verify controller signatures meet current threshold
  5. Update: sner, serder, ilk ONLY (key state unchanged)
```

---

## 12. Sequence Number Validation and Recovery

Rotation events have complex sequence number rules to support recovery:

```
Given: event sn, kever.sn (current), kever.lastEst.s (last establishment sn)

Case 1: sn > kever.sn + 1
  → Out-of-order. Escrow for later processing.

Case 2: sn == kever.sn + 1
  → Normal next event. Verify prior digest matches kever.serder.said.

Case 3: kever.lastEst.s < sn <= kever.sn (rotation recovery)
  → Recovery rotation superseding interaction events.
  → For rot: sn must be > lastEst.s (strictly)
  → For drt: sn must be >= lastEst.s
  → Verify prior digest matches the event at sn-1.

Case 4: sn <= kever.lastEst.s
  → Stale event. Cannot supersede an establishment event with another
     establishment event at the same or lower sn.
  → Reject.

Case 5: sn == kever.sn and different SAID
  → Likely duplicitous. Escrow for external resolution.
```

**Recovery example:**

```
sn  ilk   SAID        Status
0   icp   EABC...     lastEst.s=0
1   ixn   EDEF...
2   ixn   EGHI...
3   ixn   EJKL...     kever.sn=3

-- Controller discovers key compromise, issues recovery rotation at sn=1 --

1   rot   EMNO...     Recovery: supersedes ixn at sn=1, lastEst.s=0 < 1 ✓
                       Prior digest must match event at sn=0 (inception)
2   ixn   EPQR...     Now builds on the recovery rotation
```

---

## 13. Non-Transferable Identifiers

An identifier is non-transferable when:
- Its inception event has an empty `n` field (no next-key digests), OR
- Its prefix uses a non-transferable derivation code (e.g., `B` for Ed25519)

Non-transferable identifiers:
- MUST NOT have any rotation events
- MUST NOT have witnesses (`b` empty at inception)
- MUST NOT anchor data (`a` empty at inception)
- Are used for witnesses and other infrastructure nodes that should never rotate
- Once established, their key state is permanent until the identifier is
  abandoned

---

## 14. Witness Model

Witnesses are non-transferable infrastructure nodes that:
- **Receive** events from the controller and store them
- **Sign** (receipt) events they have accepted
- **Detect** if a controller publishes different events at the same sequence
  number (duplicity)
- **Provide** events to validators on request

**Witnesses do NOT add trust.** They provide availability and accountability.
A controller that publishes conflicting events to different witnesses will be
detected because witness receipts are publicly verifiable.

**Witness signature flow:**
1. Controller publishes event to witnesses
2. Witnesses return receipts to controller
3. Controller attaches witness receipts when promulgating to validators
   (via `-B` counter)
4. Validators can ALSO collect receipts independently via `processReceipt()`
5. Validators verify witness sigs without contacting witnesses directly
   (ambient verifiability)

**Witness identifiers are non-transferable** — they use non-transferable prefix
codes and have no next-key commitments. This simplifies the trust model: a
witness key is permanent for the lifetime of that witness identifier.

---

## 15. TOAD (Threshold of Accountable Duplicity)

The TOAD is the minimum number of witness receipts required before an event is
considered sufficiently witnessed.

**Ample formula (default TOAD calculation):**

```
ample(n, f=None, weak=True) → int

  Given n witnesses:
  1. If f not specified: f = max fault tolerance = (n - 1) // 3
  2. Verify: n >= 3*f + 1  (Byzantine fault tolerance requirement)
  3. Compute: m = ceil((n + f + 1) / 2)
  4. If weak: m = max(m, 1)  (at least 1 witness receipt)
  5. Return m
```

| Witnesses (n) | Max faults (f) | Default TOAD |
|--------------|----------------|--------------|
| 0 | 0 | 0 |
| 1 | 0 | 1 |
| 2 | 0 | 2 |
| 3 | 0 | 2 |
| 4 | 1 | 3 |
| 5 | 1 | 3 |
| 6 | 1 | 4 |
| 7 | 2 | 5 |
| 10 | 3 | 7 |

---

## 16. Receipt Event Structure and Attachment Types

A receipt (`rct`) event identifies the receipted event by `(i, s, d)` — the
AID, sequence number, and SAID. Signatures are attached separately in CESR
attachment groups.

**Receipt attachment types:**

| Type | Format | Use case |
|------|--------|----------|
| Non-transferable receipt couple | (Prefixer, Cigar) | Witness receipt: witness prefix + signature |
| Transferable receipt quadruple | (Prefixer, Number, Diger, Siger) | Validator receipt: receiptor AID, sn, digest, indexed sig |
| Witness indexed signature | Siger | When witness is in the current witness list: signature indexed by position |

**CESR attachment framing:** In the CESR protocol stream, receipt signatures
are framed by CESR counter codes that indicate group type and count.

| Counter (v1.0) | Type | Use case |
|---------|------|----------|
| `-A` | Controller indexed signatures | Controller's own sigs on their event |
| `-B` | Witness indexed signatures | Witness receipt (indexed by position in witness list) |
| `-C` | Non-transferable receipt couples | (Prefixer, Cigar) |
| `-D` | Transferable receipt quadruples | (Prefixer, Number, Diger, Siger) |
| `-G` | Seal source couples | (snu, dig) of anchoring event |
| `-I` | Seal source triples | (pre, snu, dig) of anchoring source event |

**Note:** These are CESR v1.0 codes. In v2.0, `-A`/`-B`/`-C`/`-D` are
reassigned to generic group types. Source: `src/keri/core/counting.py`
lines 58-61 (v1.0), lines 193-200 (v2.0).

See the CESR specification for the complete counter code table and framing
rules.

---

## 17. Witness Signature Verification

```
Verify witness signatures for event:

  1. For each witness receipt (cigar or indexed siger):
     a. Verify signature against event serialization
     b. If cigar: check cigar.verfer.qb64 is in the event's witness list
     c. If siger: check siger.index maps to a valid witness position
  2. Collect unique verified witness indices
  3. Check: len(verified_witness_indices) >= TOAD
```

---

## 18. Local vs. Remote Event Source Model

Events are categorized by their source relative to the processing agent:

| Source | Meaning | Trust level |
|--------|---------|-------------|
| **Local** | Event generated by the controller itself or received from a protected channel | Higher trust: skips some escrow checks |
| **Remote** | Event received from an unprotected external source | Lower trust: full escrow pipeline |

The distinction affects:
- Whether misfit source escrow is triggered
- Whether witness signature requirements are applied
- Processing priority and escrow behavior

---

## 19. Delegated Identifiers

Delegation allows one identifier (the delegator) to authorize the creation and
rotation of another identifier (the delegate). The delegate's events are valid
only if the delegator has anchored a corresponding seal in its own KEL.

A delegated identifier is created with a `dip` (delegated inception) event
that includes a `di` field identifying the delegator. All subsequent
establishment events use `drt` (delegated rotation) instead of `rot`.

**Key difference from non-delegated identifiers:** Every establishment event
for a delegated identifier requires an anchoring seal in the delegator's KEL.
The delegator must explicitly approve each key change.

---

## 20. Delegation Seal Mechanism

The delegator approves a delegate's event by anchoring an EventSeal in its
own KEL:

```
Delegator's KEL:
  ixn or rot event with anchor:
    a: [{ i: delegate_prefix, s: delegate_sn, d: delegate_said }]

Delegate's KEL:
  dip or drt event with:
    di: delegator_prefix
```

**Verification:** When processing a `dip` or `drt` event, the processor MUST
find a matching EventSeal in the delegator's KEL where:
- `seal.i` == delegate's AID prefix
- `seal.s` == delegate event's sequence number
- `seal.d` == delegate event's SAID

---

## 21. Delegation Validation by Party

Different parties validate delegation differently:

| Party | Responsibility | Checks |
|-------|---------------|--------|
| **Controller** (delegate) | Signs the dip/drt event | Key threshold, pre-rotation commitment |
| **Delegator** | Anchors seal in own KEL | Reviews delegate event, publishes seal |
| **Witness** | Receipts delegate event | Signature threshold, TOAD |
| **Validator** | Verifies entire chain | All of the above + delegation seal exists |

---

## 22. DoNotDelegate Trait

If a delegator's inception event includes the `DND` (DoNotDelegate) trait in
its `c` field, that identifier MUST NOT serve as a delegator. Any `dip` event
referencing a `DND` identifier as delegator MUST be rejected.

---

## 23. Superseding Recovery Rules

Both delegated and non-delegated identifiers support recovery via superseding
rotation events. The rules are precise and asymmetric between `rot` and `drt`.

### Non-Delegated Superseding Rules (A-rules)

**Rule A0:** A `rot` at sequence number `sn` supersedes an `ixn` at the same
`sn` if:
- `lastEst.s < sn <= kever.sn` (sn is STRICTLY GREATER than last
  establishment sn)
- The current state at `sn` was set by an `ixn` (not a `rot`)

**Rule A1:** A `rot` MUST NOT supersede another `rot` at the same sequence
number. Recovery rotation can only override interaction events.

**Rule A2:** An `ixn` MUST NOT supersede any event.

**Kevery acceptance condition for non-delegated recovery:**
```
ilk == rot AND lastEst.s < sn <= kever.sn
```

### Delegated Superseding Rules (B-rules)

**Rule B0:** A `drt` at sequence number `sn` supersedes an `ixn` at the same
`sn` if:
- `lastEst.s <= sn <= kever.sn` (sn can EQUAL last establishment sn — more
  permissive than `rot`)

**Rule B1:** A `drt` supersedes a prior `drt` at the same `sn` if the new
delegation seal is in a **later** event in the delegator's KEL (higher sn in
delegator's KEL).

**Rule B2:** If the delegation seals are in the **same** delegator event
(same SAID), the new `drt` supersedes if its seal appears at a **higher index**
(i.e., later position) in the seal list. The seal appearing later in the anchor
array takes precedence. Confirmed at `eventing.py:3156`.

**Rule B3:** If the delegation seals are at the **same** delegator sn but
different events, the new `drt` supersedes if the delegator's anchoring event
is a `drt` while the old one is an `ixn`.

**Kevery acceptance condition for delegated recovery:**
```
ilk == drt AND lastEst.s <= sn <= kever.sn
```

Note the asymmetry: `rot` requires `sn > lastEst.s` (strict), while `drt`
allows `sn == lastEst.s` (non-strict). This gives delegators more recovery
authority.

### Recursive Rules (C-rules)

**Rule C:** When the delegator is itself delegated, apply the A/B rules
recursively up the delegation chain. Each delegating event must satisfy the
superseding rules relative to its own delegator.

**Rule C1:** If the chain reaches a root (non-delegated) KEL without
satisfying the superseding rules, the recovery is invalid and MUST be
discarded.

### Superseding Summary Table

| Event | Can supersede | Condition on sn | Additional constraint |
|-------|--------------|-----------------|----------------------|
| `rot` → `ixn` | Yes | `lastEst.s < sn <= kever.sn` | Current ilk must be `ixn` |
| `rot` → `rot` | No | — | Rule A1 forbids this |
| `drt` → `ixn` | Yes | `lastEst.s <= sn <= kever.sn` | — |
| `drt` → `drt` | Yes | `lastEst.s <= sn <= kever.sn` | Delegator event must be later (B1-B3) |
| `ixn` → any | No | — | Rule A2 forbids this |
