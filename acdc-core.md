# ACDC Core: Credential Structure, Sections, and Variants

**Version:** 0.4.1-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** CESR specification, KERI specification
**Related specs:** [Disclosure](acdc-disclosure.md), [TEL](acdc-tel.md), [Verification](acdc-verification.md), [IPEX](acdc-ipex.md), [Appendix](acdc-appendix.md)

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Dependency Graph](#2-dependency-graph)
3. [Layer 0: Cryptographic Encoding (CESR)](#3-layer-0-cryptographic-encoding)
4. [Layer 1: Identity and Trust (KERI)](#4-layer-1-identity-and-trust)
5. [Layer 2: Content Addressing and Schema](#5-layer-2-content-addressing-and-schema)
6. [Layer 3: Credential Structure](#6-layer-3-credential-structure)
7. [Layer 4: Sections](#7-layer-4-sections)
8. [Layer 5: Credential Variants](#8-layer-5-credential-variants)

---

## 1. Design Principles

1. **Concepts are types, not flags.** A credential variant is a distinct type with
   compile-time (or construction-time) constraints, not a bag of optional fields
   where validity is checked after the fact.

2. **Layers depend downward only.** No concept at layer N references concepts at
   layer N+1. Dependencies are strictly acyclic.

3. **Composition over configuration.** Disclosure policies, edge graphs, and rule
   sets are composed from small, well-defined units -- not configured via sprawling
   parameter lists.

4. **Roles constrain operations.** Each role (Issuer, Holder, Verifier, etc.)
   defines a bounded interface of permitted operations. Operations outside that
   interface are unrepresentable, not merely forbidden at runtime.

5. **Separation of structure and encoding.** The domain model is independent of
   wire format. CESR, JSON, CBOR, MGPK are serialization strategies applied to
   the same abstract structure.

6. **Disclosure is a first-class concept.** Disclosure is not "omitting fields" --
   it is a typed transformation from one credential representation to another,
   with cryptographic proof that the transformation is valid.

7. **Two proofs for every disclosure.** Every credential presentation requires both
   a Proof of Issuance (Issuer's signature on the most compact form SAID) and a
   Proof of Disclosure (Discloser's commitment to the disclosed variant).

---

## 2. Dependency Graph

```
Layer 10: Credential Graphs & Graph-Level Disclosure ── DAGs, graph-level disclosure
    |
Layer 9:  Exchange Protocol (IPEX) ──────────────── apply/offer/agree/grant/admit/spurn (non-normative baseline)
    |
Layer 8:  Roles ─────────────────────────────────── Issuer, Holder, Verifier, ...
    |
Layer 7:  Lifecycle & State (TEL) ───────────────── issuance, revocation, registry, bulk issuance
    |
Layer 6:  Disclosure ────────────────────────────── compact/full/selective/partial/graduated/contractual/contingent
    |
Layer 5:  Credential Variants ───────────────────── public/private x targeted/untargeted x attributed/aggregated
    |                                                + Metadata ACDC (special Private subcase)
Layer 4:  Sections ──────────────────────────────── attribute, aggregate, edge, rule, schema
    |
Layer 3:  Credential Structure ──────────────────── top-level fields, version string, field ordering, SAID binding
    |
Layer 2:  Content Addressing & Schema ───────────── SAID, SAD, JSON Schema, type-is-schema
    |
Layer 1:  Identity & Trust (KERI) ───────────────── AID, KEL, key state, seals, witnesses, delegation
    |
Layer 0:  Cryptographic Encoding (CESR) ─────────── primitives, code tables, composability, serialization
```

Each layer's concepts are defined in terms of the layers below it. No upward
references. An implementation MAY collapse adjacent layers into a single module
but MUST NOT introduce upward dependencies.

---

## 3. Layer 0: Cryptographic Encoding

**Source specification:** CESR (Composable Event Streaming Representation)

This layer provides the encoding substrate. ACDC does not define any encoding
concepts -- it consumes them.

### Concepts consumed by ACDC

| Concept | What ACDC needs from it |
|---------|------------------------|
| **Primitive** | A typed, self-framing, cryptographically qualified byte sequence. All ACDC field values that carry cryptographic meaning (digests, signatures, public keys, nonces) are CESR primitives. |
| **Composability** | `T(cat(b[k])) = cat(T(b[k]))` -- primitives concatenate in text or binary domain without framing ambiguity. ACDC credentials can be streamed alongside KERI events. |
| **Code Table** | Maps 1-to-4 character prefixes to (type, length) pairs. ACDC uses codes for digests (`E` = Blake3-256), signatures (`0B` = Ed25519), AIDs (`D` = Ed25519 verkey), datetime (`1AAG`), count codes for groups. |
| **Serialization Kinds** | JSON, CBOR, MGPK, CESR-native. ACDC structures MUST be serializable in all four. The `KKKK` field in the version string selects the kind. |
| **Cold Start** | Tritet-dispatch enables ACDC messages to be identified and parsed from an arbitrary position in a CESR stream. |
| **SAD Path Language** | Path strings (e.g., `-a-personal-name`) address nested fields within a credential. Used by transposable signatures to bind proofs to specific credential sections. |

### Non-dependency

CESR has **no knowledge** of ACDC. It provides encoding; ACDC provides semantics.

---

## 4. Layer 1: Identity and Trust

**Source specification:** KERI (Key Event Receipt Infrastructure)

This layer provides the trust substrate. ACDC does not define identity or key
management -- it consumes them.

### Concepts consumed by ACDC

| Concept | What ACDC needs from it |
|---------|------------------------|
| **AID** (Autonomic Identifier) | A self-certifying identifier derived from a public key or inception event digest. Every ACDC issuer is identified by an AID. Every targeted issuee is identified by an AID. |
| **Key State** | The current set of authoritative signing keys and thresholds for an AID, derived by replaying its KEL. Required to verify any signature on an ACDC. |
| **KEL** (Key Event Log) | Immutable, append-only log of key events for an AID. ACDC issuance and revocation events are anchored to the issuer's KEL via seals. |
| **Seal** | A digest or event reference embedded in a KEL interaction event (`ixn`) that cryptographically binds an external datum (credential SAID, TEL event) to a specific key state. |
| **Delegation** | Hierarchical AID creation via `dip`/`drt` events. A delegated AID can serve as an ACDC issuer; validators must verify the delegation chain. Used by the `DI2I` edge operator. |
| **Witness** | Infrastructure nodes that provide fault-tolerant KEL availability and agreement (KAWA). ACDC verification depends on being able to retrieve the issuer's KEL. |
| **OOBI** | Out-of-band introduction -- an `(AID, URL)` pair that bootstraps discovery of an AID's KEL and endpoints. Required for any ACDC exchange between parties that don't already know each other's infrastructure. |

### Boundary

KERI provides: "this AID controls these keys at this point in time."
ACDC provides: "this AID asserts these claims, verifiably."

**Cross-reference:** See KEL Specification for detailed event structure, key
state model, and seal types.

---

## 5. Layer 2: Content Addressing and Schema

**Dependencies:** Layer 0 (CESR primitives, serialization)

This layer defines how data becomes self-addressing and self-typing.

### 5.1 SAID (Self-Addressing Identifier)

A SAID is a CESR-qualified cryptographic digest of a serialized data structure,
embedded within that same structure. It provides content-addressable identity.

**Interface:**

```
SAID:
  derive(fields: OrderedMap, digest_algorithm: DigestCode) -> SAID
  verify(fields: OrderedMap, expected: SAID) -> bool
```

**Algorithm:**
1. Set the `d` field to a dummy string of `#` characters matching the digest code's output length.
2. Serialize canonically (compact JSON with insertion-ordered fields, or equivalent canonical form for CBOR/MGPK).
3. Compute digest over the serialized bytes.
4. Encode digest as a CESR primitive.
5. Replace the dummy `d` field with the encoded digest.

**Invariant:** `verify(fields, fields.d) == true` for any correctly constructed SAD.

### 5.2 SAD (Self-Addressing Data)

Any data structure containing a `d` field whose value is the SAID of that
structure. All ACDC blocks with a `d` field are SADs.

**Properties:**
- Immutable: changing any field invalidates the SAID.
- Content-addressable: two SADs with the same SAID have identical content.
- Composable: a SAD can be replaced by its SAID (compact form) without losing the ability to verify it later.

### 5.3 Schema

ACDC uses JSON Schema for structural validation, with one critical constraint:
**type-is-schema** -- the schema SAID *is* the credential type identifier.

**Interface:**

```
Schema:
  said: SAID                          -- content address of the schema itself
  validate(data: Map) -> Result       -- structural validation
  compose(other: Schema) -> Schema    -- via JSON Schema $ref
```

**Invariants:**
- Schema `$id` field MUST be a bare SAID (no URI prefix).
- Schemas are immutable: changing a schema produces a new SAID, which is a new type.
- Schema composition via `$ref` is by SAID, enabling DAG-structured type hierarchies.

---

## 6. Layer 3: Credential Structure

**Dependencies:** Layer 2 (SAID, SAD, Schema), Layer 1 (AID)

This layer defines the raw structural skeleton of an ACDC -- the ordered field
map, field semantics, and the compact/expanded duality.

### 6.1 Version String

The version string `v` encodes protocol identity, version, serialization kind,
and message size in a fixed 19-character format:

```
PPPPMmmGggKKKKSSSSS.
```

| Segment | Length | Meaning |
|---------|--------|---------|
| `PPPP` | 4 | Protocol identifier (always `ACDC` for credentials) |
| `Mmm` | 3 | Major version (1 char) + minor version (2 chars) |
| `Ggg` | 3 | Genus (protocol genus code) |
| `KKKK` | 4 | Serialization kind: `JSON`, `CBOR`, `MGPK`, or `CESR` |
| `SSSSS` | 5 | Size of the serialized message in hexadecimal |
| `.` | 1 | Terminator |

### 6.2 Top-Level Fields

An ACDC is a SAD with the following fields, which when present MUST appear in
this order:

| Position | Field | Type | Required | Semantics |
|----------|-------|------|----------|-----------|
| 0 | `v` | VersionString | MUST | Protocol ID (`ACDC`), version, serialization kind, size (19 chars, format `PPPPMmmGggKKKKSSSSS.`) |
| 1 | `t` | MessageType | conditional | 3-char message type (see Message Type Codes below) |
| 2 | `d` | SAID | MUST | Self-addressing identifier of this credential |
| 3 | `u` | Nonce | MAY | Salty nonce; presence controls privacy variant. An **empty** `u` field (present but zero-length) denotes a Metadata ACDC. |
| 4 | `i` | AID | MUST | Issuer identifier |
| 5 | `rd` | SAID | MAY | Registry identifier (TEL anchor) |
| 6 | `s` | SAID \| SchemaBlock | MUST | Schema (compact or expanded) |
| 7 | `a` | SAID \| AttributeBlock | MAY | Attributes (mutually exclusive with `A`) |
| 8 | `A` | SAID | MAY | Attribute aggregate (mutually exclusive with `a`) |
| 9 | `e` | SAID \| EdgeBlock | MAY | Edges (chaining to other ACDCs) |
| 10 | `r` | SAID \| RuleBlock | MAY | Rules (Ricardian contracts) |

#### Message Type Codes

The `t` field identifies the ACDC message type. Defined type codes:

| Type Code | Name | Description | Distinguishing Trait |
|-----------|------|-------------|----------------------|
| `acm` | ACDC Map | Variable-field ACDC (Mapper-based, flexible field set) | `a` OR `A` (either, but not both) |
| `act` | ACDC Targeted/Attributed | Fixed-field ACDC with attribute section | `a` (MUST be present) |
| `acg` | ACDC Aggregated | Fixed-field ACDC with aggregate section | `A` (MUST be present) |
| `ace` | ACDC Extra | Experimental: allows extra fields beyond the normative set | Non-normative |

The `acm` type uses optional fields (`t`, `u`, `rd`, `a`, `A`, `e`, `r`) and
alternates (`a`/`A`), making it the most flexible variant. The `act` and `acg`
types use fixed field sets with no optional fields (all fields are always present,
defaulting to empty values when not supplied).

**`t` field optionality by type:** For `acm` (map) ACDCs, `t` is optional --
real vLEI credentials may omit it. For `act` (targeted) and `acg` (aggregated)
ACDCs, `t` is required. Implicit ACDCs (no type code) have `t` absent entirely.

### 6.3 Reserved Fields

These field labels have fixed semantics at ALL nesting levels and MUST NOT be
redefined by schemas:

| Field | Semantics |
|-------|-----------|
| `d` | SAID of the enclosing block |
| `u` | Salty nonce / blinding factor |
| `i` | Context-dependent AID (issuer at top level, issuee in attributes) |
| `rd` | Registry SAID |
| `dt` | ISO-8601 datetime with microsecond precision |
| `n` | Node SAID (edges -- identifies this as an edge vs. edge-group) |
| `s` | Schema SAID (ACDC protocol) or sequence number (KERI protocol) |

**Version note on `rd`/`ri`:** ACDC v1 (KERI protocol `pvrsn.major == 1`) uses
the field label `ri` for the registry identifier. ACDC v2 uses `rd`. The
`SerderACDC.regid` property abstracts this difference, returning the value from
whichever field is present based on the protocol version.

**Note on `s` field:** The `s` field means schema SAID in the ACDC protocol but
sequence number in the KERI protocol. Context is disambiguated by the protocol
identifier in the version string (`ACDC` vs `KERI`).

### 6.4 Compact Form and Most Compact Form

Any section (block with a `d` field) MAY be replaced by its SAID. This is
**compact form** -- a lossless compression that preserves verifiability.

```
CompactForm:
  compact(section: SAD) -> SAID       -- replace block with its d value
  expand(said: SAID, store: Store) -> SAD  -- retrieve block by SAID
  is_compact(field_value: SAID | Map) -> bool
```

**Invariant:** `compact(section) == section.d` always holds.

This duality (expanded <-> compact) is the foundation of all disclosure mechanisms.

#### Most Compact Form SAID

The **most compact form** is the unique representation obtained by recursively
compacting all sections to their SAIDs. There is ONE AND ONLY ONE most compact
form SAID for any ACDC.

**Algorithm (depth-first):**
1. Start at the leaf nodes of the credential structure (innermost nested blocks).
2. Compute the SAID of each expanded leaf block.
3. Replace each leaf block with its SAID (compact the leaf).
4. Move up: compute the SAID of the enclosing block (which now contains compacted leaves).
5. Replace the enclosing block with its SAID.
6. Repeat until the top-level credential structure is reached.
7. The resulting top-level `d` field value is the **most compact form SAID**.

**Special case:** The Aggregate section `A` uses its own aggregation algorithm
(concatenation of attribute SAIDs followed by digest), NOT the most compact SAID
algorithm. When computing the most compact form, the `A` field's value is used
as-is.

**Invariant:** The most compact form SAID is what the Issuer signs. This single
signature provides Proof of Issuance for ANY schema-authorized variant of the
credential.

#### Hash Tree Analogy

The different variants of a credential (expanded, partially compacted, fully
compacted) form a **hash tree** analogous to a Merkle Tree. The most compact
form SAID is the root. Different disclosure variants correspond to different
paths through this tree. Signing the most compact form SAID is equivalent to
signing the Merkle Root -- a single signature covers all valid variants.

---

## 7. Layer 4: Sections

**Dependencies:** Layer 3 (credential structure, compact form), Layer 2 (SAID, Schema)

Sections are the composable building blocks of credential content. Each section
is independently SAIDed, independently compactable, and independently disclosable.

### 7.1 AttributeSection

Contains the asserted claims. This is the "payload" of the credential.

**Interface:**

```
AttributeSection:
  said: SAID                          -- content address
  nonce: Nonce?                       -- if present, section is private (INDEPENDENT of top-level u)
  issuee: AID?                        -- if present, credential is targeted
  fields: OrderedMap<string, Value>   -- the actual claims
  datetime: DateTime?                 -- issuance timestamp
  cargo: Opaque?                      -- enables ACDCs as opaque data containers
```

**Privacy independence:** The attribute section has its OWN `u` field that is
independent of the top-level `u` field. This means:
- Top-level `u` controls credential-level privacy (whether the credential SAID is blinded).
- Attribute section `u` controls attribute-level privacy (whether the attribute block content is blinded).
- These are INDEPENDENT -- you can have a public credential with private attributes, or a private credential with public attributes.

**Variants by privacy:**
- `nonce` present -> **Private attribute section** (SAID is blinded; cannot be brute-forced)
- `nonce` absent -> **Public attribute section** (SAID is verifiable by anyone with the data)

**Variants by targeting:**
- `issuee` present -> **Targeted** (credential is bound to a specific AID)
- `issuee` absent -> **Untargeted** (credential is bearer-like)

**Cargo field:** The `cargo` field enables ACDCs to serve as opaque data
containers. When present, it encapsulates arbitrary data formats within the
credential structure, allowing ACDCs to carry payloads beyond structured claims
(e.g., binary blobs, domain-specific encodings).

### 7.2 AggregateSection

An alternative to AttributeSection that enables selective disclosure at the
individual-attribute level. Instead of a single block of attributes, each
attribute is independently SAIDed and the aggregate is a digest of their
concatenated SAIDs.

**Interface:**

```
AggregateSection:
  aggregate_said: SAID                -- AGID: digest of concatenated attribute SAIDs

  derive(attributes: List<AttributeBlock>) -> SAID
  verify(attributes: List<AttributeBlock>, expected: SAID) -> bool
  prove_inclusion(attribute: AttributeBlock, all_saids: List<SAID>) -> InclusionProof
```

**AGID Computation:**
1. Compute SAID of each individual attribute block.
2. Concatenate all SAIDs in schema-defined order.
3. Compute digest of the concatenation.
4. The result is the Attribute Aggregate Identifier (AGID).

**Mutual Exclusion:** A credential MUST have either `a` (AttributeSection) or
`A` (AggregateSection), never both, never neither (unless the credential is
schema-only with no claims).

### 7.3 EdgeSection

Defines typed, directed edges to other ACDCs, forming a verifiable credential
graph (DAG). Edges express provenance, delegation, and dependency relationships.

**Interface:**

```
EdgeSection:
  said: SAID
  nonce: Nonce?                       -- if present, edges are private
  edges: OrderedMap<string, Edge>     -- labeled edges to other ACDCs
  operators: OperatorSet?             -- constraints on the edge group

Edge:
  node_said: SAID                     -- SAID of the target ACDC (REQUIRED)
  schema: SAID?                       -- required schema of the target
  operators: OperatorSet?             -- per-edge constraints
  weight: Weight?                     -- for weighted threshold operators (w field)
```

**Operators** constrain the relationship between the issuer of this ACDC and the
issuee/issuer of the target ACDC. Operators apply to edge-groups. Individual edges
within a group inherit the group operator unless overridden.

#### Unary Operators (per-edge)

| Operator | Constraint |
|----------|------------|
| `I2I` | **Issuer-to-Issuee**: the Issuer of the current ACDC MUST be the **Issuee** of the target ACDC. This is the **default** for edges pointing to targeted ACDCs. If the target ACDC is untargeted (has no `i` field in its attribute section), the I2I constraint CANNOT be satisfied and verification fails. |
| `NI2I` | **Not-Issuer-to-Issuee**: removes/nullifies the I2I requirement. The Issuer of the current ACDC need NOT be the Issuee of the target. This is the **default** for edges pointing to untargeted ACDCs. |
| `DI2I` | **Delegated-Issuer-to-Issuee**: the Issuer of the current ACDC MUST be the Issuee of the target ACDC OR a delegated AID of that Issuee (verified via KERI delegation chain). **Implementation note:** the keripy reference implementation does not yet implement DI2I verification (`verifying.py` raises `NotImplementedError`). Implementations targeting this operator should expect it to require KERI delegation chain verification. |
| `NOT` | **Negation**: inverts the validation truthiness of the far (target) node. If the target would validate as true, `NOT` makes it validate as false, and vice versa. |

#### M-ary Operators (edge-group level)

| Operator | Constraint |
|----------|------------|
| `AND` | All edges in the group must be satisfied. This is the **default** m-ary operator. |
| `OR` | At least one edge in the group must be satisfied. |
| `WAVG` | **Weighted Average**: computes a weighted average over the truthiness values of the edges in the group, using each edge's `w` (weight) field. The group is satisfied when the weighted average meets or exceeds a threshold. |

**Operator defaulting:** When no operator is specified on an edge, the default
is determined by the target credential: if the target has an `i` field
(issuee) in its attributes, the default is `I2I`; otherwise, the default is
`NI2I`. This ensures that targeted credentials are chain-verified by default
while untargeted credentials are not.

**Weight field:** Each edge MAY have a `w` (weight) field specifying its weight
for use with the `WAVG` operator. Weights are numeric values. When `WAVG` is the
group operator, each edge's `w` field contributes to the weighted average
computation.

**Invariant:** An edge section without `n` is an **edge-group** (container). An
entry with `n` is an **edge** (leaf). This distinction MUST be enforced structurally.

### 7.4 RuleSection

Contains machine-readable legal language (Ricardian contracts) that governs the
credential's use. Rules bind issuance to contractual obligations.

**Interface:**

```
RuleSection:
  said: SAID
  rules: OrderedMap<string, Rule>     -- labeled rules
  operators: OperatorSet?             -- how rules compose

Rule:
  legal_text: string                  -- REQUIRED: human-readable legal language
  properties: OrderedMap?             -- additional rule metadata
```

**Invariant:** Every Rule block MUST contain an `l` (legal text) field.

### 7.5 Section Messages (v2)

In ACDC v2, each section is independently serializable as a typed message with
its own version string and SAID. This enables sections to be transmitted,
stored, and disclosed independently of the top-level credential.

The `sectionate()` function creates the ACDC in its most compact form AND the
corresponding section messages as a tuple `(acdc, sch, att, agg, edg, rul)`.

**Section message types:**

| Type Code | Name | Fields | Purpose |
|-----------|------|--------|---------|
| `sch` | Schema Section | `v, t, d, s` | Independently transmit schema |
| `att` | Attribute Section | `v, t, d, a` | Independently transmit attributes |
| `agg` | Aggregate Section | `v, t, d, A` | Independently transmit aggregate |
| `edg` | Edge Section | `v, t, d, e` | Independently transmit edges |
| `rul` | Rule Section | `v, t, d, r` | Independently transmit rules |

Each section message is a full ACDC protocol message with its own version
string (protocol `ACDC`), message type, and SAID. This means sections can be:
- Transmitted separately (e.g., disclosed at different times in graduated disclosure)
- Cached and resolved independently by SAID
- Verified in isolation before composing into a full credential

### 7.6 SchemaSection

The credential's type definition. Unique among sections because the schema SAID
doubles as the credential's type identifier (type-is-schema).

**Interface:**

```
SchemaSection:
  said: SAID                          -- this IS the type ID
  json_schema: JSONSchema             -- structural validation rules

  validate(credential: Credential) -> ValidationResult
  compose(other: SchemaSection) -> SchemaSection  -- via $ref
```

---

## 8. Layer 5: Credential Variants

**Dependencies:** Layer 4 (all sections), Layer 3 (nonce field)

ACDC credentials exist in a combinatorial space defined by two orthogonal
dimensions plus a functional variant. The two dimensions produce 8 core
combinations (2 x 2 x 2). The Metadata ACDC is a special case of the Private
variant used for pre-disclosure negotiation, not a separate dimension.

### 8.1 Dimension 1: Visibility

Controlled by the presence/absence/value of the top-level `u` (nonce) field.

| Variant | Top-level `u` | SAID property |
|---------|---------------|---------------|
| **Public** | absent | SAID is freely verifiable; anyone with the content can confirm the digest |
| **Private** | present (high-entropy value) | SAID is blinded; the nonce adds entropy making brute-force infeasible |

### 8.2 Dimension 2: Targeting

Controlled by the presence/absence of the `i` (issuee) field in the attribute
section.

| Variant | Issuee AID | Semantics |
|---------|------------|-----------|
| **Targeted** | present | Credential is bound to a specific holder; only that AID can legitimately present it |
| **Untargeted** | absent | Credential is bearer-instrument-like; any holder can present it |

### 8.3 Dimension 3: Attribute Mode

Controlled by which of the mutually exclusive fields is present.

| Variant | Field | Disclosure granularity |
|---------|-------|----------------------|
| **Attributed** | `a` | Section-level disclosure (all-or-nothing for the attribute block) |
| **Aggregated** | `A` | Attribute-level selective disclosure (individual fields can be revealed independently) |

### 8.4 Variant Matrix

The 8 core combinations (2 x 2 x 2) are:

| Visibility | Targeting | Attr Mode | Use Case |
|------------|-----------|-----------|----------|
| Public + Targeted + Attributed | | | Standard verifiable credential (e.g., diploma) |
| Public + Targeted + Aggregated | | | Public credential with selective attribute disclosure |
| Public + Untargeted + Attributed | | | Public attestation (e.g., product certification) |
| Public + Untargeted + Aggregated | | | Public bearer credential with selective disclosure |
| Private + Targeted + Attributed | | | Privacy-preserving targeted credential |
| Private + Targeted + Aggregated | | | Privacy-preserving identity credential with selective disclosure |
| Private + Untargeted + Attributed | | | Anonymous bearer credential |
| Private + Untargeted + Aggregated | | | Anonymous survey response with selectively provable fields |

### 8.5 Metadata ACDC (Functional Variant)

A Metadata ACDC is a **special case of a Private ACDC** used for pre-disclosure
negotiation. It is NOT a third visibility dimension. Its defining characteristic
is that the `u` field is present but **empty** (zero-length), rather than
containing a high-entropy nonce.

**Purpose:** The Metadata ACDC allows a Discloser to make commitments about
credential metadata (schema, rules, structure) without correlating to the actual
ACDC's SAID. Because the empty `u` produces a different digest than a
high-entropy `u`, the Metadata ACDC has a DIFFERENT SAID than the eventual
disclosed credential.

**Three distinct `u` field states** (each produces a DIFFERENT SAID):

| State | `u` value | `.uuid` property | CESR code | Variant |
|-------|-----------|------------------|-----------|---------|
| Absent | field not in SAD | `None` | not encoded | Public ACDC (`acm` only, since `u` is optional) |
| Empty | `""` (zero-length string) | `""` | `NonceDex.Empty` | **Metadata ACDC** |
| High-entropy | qb64 nonce | qb64 string | `NonceDex.Salt_128` | Private ACDC |

Note: For fixed-field types (`act`, `acg`), the `u` field is always present
(not optional). When not supplied, it defaults to empty string, making the
default a Metadata ACDC. For `acm` (variable-field), `u` is optional and
absent by default, making the default a Public ACDC.

**Properties:**
- The `u` field is present but empty (not absent, not high-entropy).
- The attribute section `a` MAY be empty or missing entirely.
- All other sections that are present are typically in compact form (SAIDs only).
- The Metadata ACDC SAID differs from the actual credential SAID, preventing
  correlation between the negotiation phase and the disclosure phase.
- Used in IPEX Offer messages for contractual negotiation before disclosure.

**Construction constraints:**
- REQUIRES `u` field to be present with empty value.
- MAY omit or empty the attribute section.
- Schema and rules sections, when present, allow the Disclosee to evaluate
  the credential type and terms without seeing content.

**Serialization and SAID differentiation:** The three `u` states (absent, empty
string, high-entropy) produce different SAIDs because they serialize differently
in JSON. This prevents correlation between Metadata ACDC and actual credential
SAIDs.

### 8.6 Variant as Type

**Interface:**

```
CredentialVariant:
  visibility: Public | Private
  targeting: Targeted | Untargeted
  attribute_mode: Attributed | Aggregated

  -- Construction-time validation:
  --   Private REQUIRES nonce field with high-entropy value
  --   Targeted REQUIRES issuee AID in attribute section
  --   Aggregated REQUIRES aggregate field, PROHIBITS attribute block

MetadataACDC:
  -- Special Private subcase for pre-disclosure negotiation
  -- REQUIRES u field present but empty (zero-length)
  -- Attribute section MAY be empty or absent
  -- Has a DIFFERENT SAID than the eventual disclosed credential
```

An implementation SHOULD make invalid variants unrepresentable. A `Private`
credential without a nonce is not a valid state to be checked at runtime -- it
should be a construction error.
