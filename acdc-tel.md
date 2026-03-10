# ACDC TEL: Lifecycle and State

**Version:** 0.4.1-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** [ACDC Core](acdc-core.md) (credential structure, AID, KEL, seals, CESR)
**Related specs:** [Verification](acdc-verification.md)

---

The Transaction Event Log (TEL) manages credential state over time. It is the
mechanism by which credentials are issued, revoked, and (optionally) blinded.

**Cross-reference:** See TEL Specification for detailed TEL event field
definitions and state machine rules.

The TEL contains TWO separate state machines: the **Registry state machine**
(managing the registry itself) and the **Credential state machine** (managing
individual credentials within a registry).

---

## 1. Registry

A registry is a TEL instance that groups related credentials under a common
governance structure.

```
Registry:
  said: SAID                          -- registry identifier
  issuer: AID                         -- controlling AID
  backers: List<AID>?                 -- witness-like infrastructure for TEL availability
  configuration: Set<RegistryTrait>   -- NoBackers, EstOnly, etc.

  -- Anchored to the issuer's KEL via a seal in an interaction event
```

**Registry Traits:**

| Trait | Semantics |
|-------|-----------|
| `NoBackers` | Registry operates without backer infrastructure; TEL events are only in the issuer's KEL |
| `EstOnly` | Registry updates are only permitted via establishment events (inception, rotation), not interaction events |

---

## 2. Registry State Machine

The registry itself has a state machine for managing its configuration and backers:

```
Registry State Machine (v1: KERI protocol):

         +------------------+
         |                  |
         |  (not created)   |
         |                  |
         +--------+---------+
                  | vcp (RegistryInception)
                  v
         +------------------+
         |                  |
         |     Active       | <-- vrt (RegistryRotation: backer updates)
         |                  | --+
         +------------------+   |
                  ^             |
                  +-------------+


Registry State Machine (v2: ACDC protocol):

         +------------------+
         |                  |
         |  (not created)   |
         |                  |
         +--------+---------+
                  | rip (RegistryInception)
                  v
         +------------------+
         |                  |
         |     Active       | <-- bup (BlindableUpdate) or upd (Update)
         |                  | --+
         +------------------+   |
                  ^             |
                  +-------------+
```

**Registry events vary by protocol version:**

**KERI protocol v1 (TEL):**
- **RegistryInception** (`vcp`): Creates a new registry, defines initial backers and configuration.
- **RegistryRotation** (`vrt`): Updates backers for the registry. Does NOT affect credential states within the registry.

**ACDC protocol v2:**
- **RegistryInception** (`rip`): Creates a new registry. Fields: `v, t, d, u, i, n, dt`.
- **BlindableUpdate** (`bup`): Blindable registry update. Fields: `v, t, d, rd, n, p, dt, b` (where `b` is the blinded state attribute block SAID).
- **Update** (`upd`): Registry update targeting a specific ACDC. Fields: `v, t, d, rd, n, p, dt, td, ts` (where `td` is the target ACDC digest and `ts` is the target state string).

---

## 3. TEL Events

TEL event types differ between protocol versions. See TEL Specification for
detailed field definitions and state machine rules.

**KERI protocol v1 TEL events:**

```
RegistryInception (vcp):              -- creates a new registry
  version: VersionString
  type: "vcp"
  said: SAID
  issuer: AID
  backers: List<AID>?
  configuration: Set<RegistryTrait>

RegistryRotation (vrt):               -- rotates registry backers
  type: "vrt"
  said: SAID
  registry: SAID
  backer_changes: BackerDelta

SimpleIssuance (iss):                 -- issues a credential (no backers)
  type: "iss"
  said: SAID
  credential_said: SAID               -- i field
  sequence: "0"                       -- s field
  registry: SAID                      -- ri field
  datetime: DateTime
  -- Anchored to issuer's KEL
  -- Registry MUST have NoBackers trait

BackedIssuance (bis):                 -- issues a credential (with backers)
  type: "bis"
  said: SAID
  credential_said: SAID               -- i field
  issuing_registry: SAID              -- ii field (NOT ri)
  sequence: "0"                       -- s field
  registry_anchor: SealEvent          -- ra field: {i, s, d}
  datetime: DateTime
  -- Anchored to issuer's KEL
  -- REQUIRES backer signatures (bigers) meeting toad threshold

SimpleRevocation (rev):               -- revokes a credential (no backers)
  type: "rev"
  said: SAID
  credential_said: SAID               -- i field
  sequence: "1"                       -- s field
  registry: SAID                      -- ri field
  prior_event: SAID                   -- p field
  datetime: DateTime
  -- Anchored to issuer's KEL

BackedRevocation (brv):               -- revokes a credential (with backers)
  type: "brv"
  said: SAID
  credential_said: SAID               -- i field
  sequence: "1"                       -- s field
  prior_event: SAID                   -- p field
  registry_anchor: SealEvent          -- ra field: {i, s, d}
  datetime: DateTime
  -- Anchored to issuer's KEL
  -- REQUIRES backer signatures (bigers) meeting toad threshold
```

**TEL field name cross-reference (v1 KERI protocol):**

Note the asymmetry between simple and backed event types. In particular, `brv`
uses NEITHER `ri` nor `ii` -- it references the registry only via the `ra` seal.

| Field | `iss` | `rev` | `bis` | `brv` |
|-------|-------|-------|-------|-------|
| Registry ref | `ri` | `ri` | `ii` | -- (via `ra`) |
| Registry anchor | -- | -- | `ra` | `ra` |
| Prior digest | -- | `p` | -- | `p` |
| Witness sigs | -- | -- | required | required |

**ACDC protocol v2 TEL events:**

```
RegistryInception (rip):              -- creates a new registry
  v: VersionString                    -- ACDC protocol version
  t: "rip"
  d: SAID
  u: Nonce                            -- UUID
  i: AID                              -- issuer
  n: HexSequenceNumber                -- must be "0" at inception
  dt: DateTime

BlindableUpdate (bup):                -- blindable registry state update
  v: VersionString
  t: "bup"
  d: SAID
  rd: SAID                            -- registry SAID (from rip)
  n: HexSequenceNumber
  p: SAID                             -- prior event SAID
  dt: DateTime
  b: SAID                             -- blindable state attribute block SAID

Update (upd):                         -- targeted registry state update
  v: VersionString
  t: "upd"
  d: SAID
  rd: SAID                            -- registry SAID (from rip)
  n: HexSequenceNumber
  p: SAID                             -- prior event SAID
  dt: DateTime
  td: SAID                            -- target ACDC digest
  ts: string                          -- target state
```

---

## 4. Credential State Machine

Each credential within a registry has its own independent state machine:

```
         +------------------+
         |                  |
         |      None        | -- (no TEL events exist for this credential)
         |                  |
         +--------+---------+
                  | CredentialIssuance
                  v
         +------------------+
         |                  |
         |     Issued       | -- credential is valid and active
         |                  |
         +--------+---------+
                  | CredentialRevocation
                  v
         +------------------+
         |                  |
         |     Revoked      | -- credential is permanently invalid
         |                  |
         +------------------+
```

**Invariants:**
- State transitions are irreversible (no un-revocation).
- Every TEL event MUST be anchored to the issuer's KEL via a seal.
- A credential's state is only authoritative if the anchoring KEL event is
  verified against the issuer's current key state.
- Registry state changes (backer rotation) and credential state changes
  (issuance/revocation) are independent operations on independent state machines.

---

## 5. Blinded State (Advanced)

For privacy-preserving registries, the credential's TEL identifier can be a
**BLID** (Blinded Ledger Identifier) rather than the credential SAID.

```
BlindedState:
  blid: SAID                          -- derived from credential SAID + blinding nonce
  -- Only parties who know the credential SAID AND the nonce can
  -- correlate TEL state to a specific credential

  derive_blid(credential_said: SAID, nonce: Nonce) -> BLID
  check_state(blid: BLID, registry: Registry) -> CredentialState
```

**Dependencies:** Nonce (Core spec, Section 6), Registry

---

## 6. Bulk Issuance

Bulk issuance enables a single Issuer signature to cover many credentials
simultaneously. This is achieved through blinded SAIDs and an aggregate digest.

**Mechanism:**

Given M credentials to issue in bulk:

```
BulkIssuance:
  credentials: List<Credential>       -- M credentials at indices 0..M-1
  blinding_factors: List<Nonce>        -- v_k for each credential at index k

  -- For each credential at index k:
  --   d_k = SAID of the credential (most compact form)
  --   v_k = blinding factor (random nonce)
  --   b_k = H(v_k + d_k)             -- blinded SAID
  --
  -- Aggregate:
  --   B = H(C(b_k for all k in {0, ..., M-1}))
  --   where C() is canonical concatenation
  --   and H() is the digest function
  --
  -- The TEL issuance event uses B (the aggregate) as the identifier.
  -- All bulk-issued credentials share a single TEL entry anchored to B.

  derive_blinded_said(credential_said: SAID, blinding_factor: Nonce) -> BlindedSAID
  derive_aggregate(blinded_saids: List<BlindedSAID>) -> Aggregate
```

**Proof of inclusion** for a bulk-issued credential requires:
1. The compact ACDC (with its most compact form SAID `d_k`).
2. The blinding factor `v_k` for that credential.
3. The full list of ALL blinded SAIDs `[b_0, b_1, ..., b_{M-1}]`.
4. The anchor reference to the TEL entry using aggregate `B`.

The verifier recomputes `b_k = H(v_k + d_k)`, confirms `b_k` appears in the
provided list, recomputes `B = H(C(all b_k))`, and confirms `B` matches the
TEL anchor.

**Three bulk issuance patterns:**

| Pattern | Description | Correlation properties |
|---------|-------------|----------------------|
| **Basic** | All credentials share issuer AID, registry, and TEL entry. | Minimal correlation resistance: verifier learns all credentials are from the same batch. |
| **Independent AID** | Each credential uses a different issuer AID (all controlled by the same entity). | Better correlation resistance: different presentations cannot be linked by issuer AID. |
| **Independent TEL** | Each credential has its own independent TEL entry (not sharing the aggregate). | Maximum correlation resistance: each credential appears independently issued. |

**Invariant:** The aggregate `B` cryptographically commits the Issuer to all M
credentials in the batch. Revoking the aggregate TEL entry revokes all credentials
in the batch.

**Note on aggregate field `A`:** The aggregate field `A` stores a SAID or list
of aggregate blocks. Implementations should consult the ACDC specification for
the aggregate digest computation algorithm.
