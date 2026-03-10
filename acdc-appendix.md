# ACDC Appendix: Graphs, Rules, Invariants, and Reference

**Version:** 0.4.0-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** All other ACDC specs

---

## 1. Credential Graphs and Graph-Level Disclosure

**Dependencies:** [IPEX](acdc-ipex.md), [TEL](acdc-tel.md), [Core](acdc-core.md) (EdgeSection)

ACDCs chain into directed acyclic graphs (DAGs) via their Edge sections. This
creates verifiable provenance chains, delegation hierarchies, and authorization
structures.

### 1.1 CredentialGraph

```
CredentialGraph:
  nodes: Map<SAID, Credential>        -- credentials indexed by SAID
  edges: Map<SAID, List<TypedEdge>>   -- adjacency list

TypedEdge:
  source: SAID                        -- credential containing the edge
  target: SAID                        -- credential referenced by the edge
  label: string                       -- edge label from schema
  operator: Operator?                 -- I2I, NI2I, DI2I, NOT, etc.

  -- Graph operations:
  provenance_chain(credential: SAID) -> List<Credential>
  verify_graph(root: SAID) -> GraphVerificationResult
  disclosure_at_depth(root: SAID, depth: Natural, policy: GraphDisclosurePolicy) -> GraphPresentation
```

### 1.2 Graph Verification

Verifying a credential graph requires recursive traversal:

```
GraphVerification:
  for each credential in topological order (leaves first):
    1. Verify credential individually (Verifier)
    2. For each edge in credential:
       a. Resolve target credential
       b. Verify target credential (recursive)
       c. Check operator constraints:
          - I2I:  credential.issuer == target.issuee
          - NI2I: no issuer-to-issuee constraint
          - DI2I: credential.issuer is delegate of target.issuee (check KEL)
          - NOT:  invert truthiness of target validation
       d. Check target matches required schema (if specified in edge)
    3. Check edge-group operators (AND/OR/WAVG with weights)
```

### 1.3 Graph-Level Disclosure

When presenting a credential with edges, the presenter must decide how much
of the graph to reveal. This concept was previously referred to as "percolated
disclosure" in informal usage. **Note:** "Percolated Disclosure" is NOT a formal
specification term -- it is an architectural concept derived from the spec's
disclosure mechanisms applied to credential graphs.

```
GraphDisclosurePolicy:
  credential_graph: CredentialGraph   -- DAG of chained ACDCs

  disclose_with_provenance(
    root: Credential,
    depth: Natural,                   -- how deep to disclose
    policy: DepthPolicy               -- what to reveal at each depth
  ) -> GraphPresentation

DepthPolicy:
  per_depth_disclosure: Map<Natural, DisclosureLevel>
  -- Controls how much is revealed at each depth in the graph
  -- Depth 0 = the root credential
  -- Depth 1 = credentials referenced by root's edges
  -- etc.

GraphPresentation:
  root: DisclosedCredential           -- the primary credential
  supporting: Map<SAID, DisclosedCredential>  -- edge credentials
  depth: Natural                      -- how deep the presentation goes

  -- Each credential in the graph may have a different disclosure level
  -- Typically: full disclosure at root, decreasing with depth
```

**Dependencies:** CredentialGraph, GraduatedDisclosure, EdgeSection

---

## 2. Composition Rules

These rules govern how concepts from different layers combine to form valid
ACDC operations.

### 2.1 Variant + Disclosure Compatibility

| Credential Variant | Compatible Disclosure Mechanisms |
|--------------------|--------------------------------|
| Public + Attributed | Full, Compact, Partial |
| Public + Aggregated | Full, Compact, Partial, Selective |
| Private + Attributed | Full, Compact, Partial, Graduated (metadata level is meaningful) |
| Private + Aggregated | Full, Compact, Partial, Selective, Graduated |
| Any + with Rules | All above + Contractually Protected, Contingent |
| Any + with Edges | All above + Graph-Level Disclosure |

Note: Metadata ACDCs are a special case of Private and are used during the
Offer step of IPEX for pre-disclosure negotiation. They are not a separate
entry in the compatibility matrix because they are a functional pattern, not
a distinct visibility variant.

### 2.2 Role + Operation Compatibility

| Operation | Issuer | Holder | Verifier | Discloser | Disclosee |
|-----------|--------|--------|----------|-----------|-----------|
| Create credential | YES | -- | -- | -- | -- |
| Revoke credential | YES | -- | -- | -- | -- |
| Bulk issue credentials | YES | -- | -- | -- | -- |
| Present credential | -- | YES | -- | -- | -- |
| Verify credential | -- | -- | YES | -- | -- |
| Disclose (any level) | -- | -- | -- | YES | -- |
| Receive disclosure | -- | -- | -- | -- | YES |
| Agree to terms | -- | -- | -- | -- | YES |
| Initiate IPEX Apply | -- | -- | -- | -- | YES |
| Initiate IPEX Offer | -- | -- | -- | YES | -- |
| Initiate IPEX Grant | -- | -- | -- | YES | -- |
| Spurn | -- | -- | -- | YES | YES |

Note: A single AID may hold multiple roles simultaneously (e.g., Holder +
Discloser is the common case). Apply can be used in both issuance and
presentation contexts.

### 2.3 Section + Section Interaction

| Section | Depends on | Constrains |
|---------|-----------|------------|
| Schema | -- | Attribute (validates structure), Edge (validates target schemas) |
| Attribute | Schema | Targeting (issuee field), Privacy (independent `u` field) |
| Aggregate | Schema | Selective Disclosure (enables per-field reveal) |
| Edge | -- | Graph structure (defines DAG), Verification (operator checks: I2I/NI2I/DI2I/NOT) |
| Rule | -- | Contractual Disclosure (binds legal terms), Contingent Disclosure |

---

## 3. Invariants

These are the universal constraints that every ACDC implementation MUST enforce.

### Structural Invariants

1. **SAID integrity**: For every block containing a `d` field, `d == SAID(block)`.
2. **Field ordering**: Fields MUST appear in the canonical order defined in the Core spec.
3. **Mutual exclusion**: `a` and `A` MUST NOT both be present with non-empty values.
4. **Reserved fields**: `d`, `u`, `i`, `rd`, `dt`, `n` retain their semantics at every nesting level.
5. **Compact equivalence**: `compact(section) == section.d` -- compacting a section always produces its SAID.
6. **Most compact form uniqueness**: There is ONE AND ONLY ONE most compact form SAID for any ACDC, computed by the depth-first algorithm defined in the Core spec.

### Privacy Invariants

7. **Nonce requirement**: A `Private` credential MUST have a top-level `u` field with sufficient entropy (128+ bits).
8. **Section nonce independence**: Each section's `u` field is independent of the top-level `u`. A private credential MAY have public sections and vice versa.
9. **Blinding irreversibility**: Given only a SAID of a private block (with `u`), it MUST be computationally infeasible to recover the block's content.
10. **Metadata ACDC distinction**: A Metadata ACDC (empty `u`) MUST produce a different SAID than the corresponding actual credential (high-entropy `u`), preventing correlation between negotiation and disclosure phases.

### Lifecycle Invariants

11. **Issuance anchoring**: Every credential issuance event MUST be anchored to the issuer's KEL via a seal.
12. **Revocation irreversibility**: Once revoked, a credential MUST NOT transition back to issued state.
13. **Key state binding**: Credential signatures are verified against the issuer's key state at the time the anchoring KEL event was created.
14. **Bulk issuance aggregate commitment**: The aggregate `B = H(C(b_k for all k))` cryptographically commits the Issuer to all credentials in the batch. The TEL entry for `B` governs the state of all included credentials.

### Disclosure Invariants

15. **Proof of Issuance requirement**: Every credential presentation MUST include the Issuer's signature on the most compact form SAID, verifiable against the Issuer's key state.
16. **Monotonic graduated disclosure**: Each level in a graduated disclosure sequence MUST reveal a strict superset of the previous level.
17. **Selective disclosure completeness**: A selective disclosure proof MUST include ALL attribute SAIDs (not just the revealed ones) for AGID recomputation.
18. **Contractual chain integrity**: Each link in a contractually protected disclosure chain MUST reference terms that are equal to or stricter than the previous link.

### Graph Invariants

19. **DAG constraint**: The credential graph defined by Edge sections MUST be acyclic.
20. **Operator consistency**: Edge operator verification (I2I, NI2I, DI2I) MUST be checked against resolved key state and actual issuee identity, not claimed identity. I2I checks that the current credential's Issuer equals the target credential's Issuee.

---

## 4. Concept Dependency Matrix

This matrix shows which concepts each layer requires from lower layers. An `X`
means the row concept depends on the column concept.

| Concept / Depends on | CESR Primitive | Serialization | SAID | AID | KEL | Seal | Key State | Schema | Compact Form | Nonce | Section | Variant | TEL |
|--------------------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **SAID** | X | X | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| **Schema** | -- | X | X | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| **Credential Structure** | X | X | X | X | -- | -- | -- | X | -- | -- | -- | -- | -- |
| **Compact Form** | -- | -- | X | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| **Attribute Section** | -- | X | X | X | -- | -- | -- | X | -- | X | -- | -- | -- |
| **Aggregate Section** | -- | X | X | -- | -- | -- | -- | X | -- | -- | -- | -- | -- |
| **Edge Section** | -- | X | X | X | -- | -- | -- | X | -- | X | -- | -- | -- |
| **Rule Section** | -- | X | X | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| **Credential Variant** | -- | -- | -- | -- | -- | -- | -- | -- | -- | X | X | -- | -- |
| **Full Disclosure** | -- | -- | -- | -- | -- | -- | -- | -- | X | -- | X | -- | -- |
| **Compact Disclosure** | -- | -- | X | -- | -- | -- | -- | -- | X | -- | X | -- | -- |
| **Selective Disclosure** | -- | -- | X | -- | -- | -- | -- | -- | X | -- | X | X | -- |
| **Graduated Disclosure** | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | X | -- |
| **Contractual Disclosure** | -- | -- | X | X | -- | -- | X | -- | -- | -- | X | -- | -- |
| **Contingent Disclosure** | -- | -- | X | X | -- | -- | X | -- | -- | -- | X | -- | -- |
| **Graph-Level Disclosure** | -- | -- | X | X | X | -- | X | X | X | -- | X | X | -- |
| **Registry** | X | X | X | X | X | X | -- | -- | -- | -- | -- | -- | -- |
| **Credential State** | -- | -- | X | -- | X | X | X | -- | -- | -- | -- | -- | X |
| **Bulk Issuance** | -- | -- | X | X | X | X | X | -- | -- | X | -- | -- | X |
| **Issuer** | -- | -- | -- | X | X | X | X | X | -- | -- | X | X | X |
| **Holder** | -- | -- | -- | X | -- | -- | -- | -- | -- | -- | -- | X | -- |
| **Verifier** | -- | -- | X | X | X | X | X | X | X | -- | X | X | X |
| **IPEX** | -- | -- | -- | X | -- | -- | X | -- | -- | -- | -- | -- | -- |
| **Credential Graph** | -- | -- | X | X | X | -- | X | X | -- | -- | X | -- | -- |

(Graph-Level Disclosure depends on Credential Graph + Graduated Disclosure, which
are at the same or higher layer -- it is the most composite concept.)

---

## Appendix A: Concept Glossary

| Term | Layer | Definition |
|------|-------|------------|
| **ACDC** | 3 | Authentic Chained Data Container -- a SAIDed, schema-typed, section-composable verifiable data structure |
| **AGID** | 4 | Attribute Group Identifier -- digest of concatenated attribute SAIDs enabling selective disclosure |
| **AID** | 1 | Autonomic Identifier -- self-certifying identifier bound to a key event log |
| **Blinding Factor** | 7 | Random nonce `v_k` used in bulk issuance to blind individual credential SAIDs, preventing correlation |
| **BLID** | 7 | Blinded Ledger Identifier -- privacy-preserving TEL identifier derived from credential SAID + nonce |
| **Bulk Issuance** | 7 | Mechanism enabling a single Issuer signature to cover multiple credentials via blinded SAIDs and an aggregate digest |
| **Cargo** | 4 | Optional field in the attribute section that enables ACDCs to serve as opaque data containers for arbitrary data formats |
| **Compact Form** | 3 | Replacing an expanded section block with its SAID |
| **Contingent Disclosure** | 6 | Special case of Contractually Protected Disclosure where a contingency clause obligates disclosure when conditions are met; enables latent accountability |
| **DI2I** | 4 | Delegated-Issuer-to-Issuee -- edge operator requiring the current ACDC's Issuer to be the target's Issuee or a delegated AID of that Issuee |
| **Disclosee** | 8 | Party receiving disclosed credential content |
| **Discloser** | 8 | Party revealing credential content under a disclosure policy |
| **Edge** | 4 | Typed, directed reference from one ACDC to another |
| **Graduated Disclosure** | 6 | Progressive multi-step revelation from metadata to full content |
| **Graph-Level Disclosure** | 10 | Disclosure that propagates through an ACDC edge graph with per-depth disclosure policies (informally called "percolated disclosure") |
| **Holder** | 8 | Party in possession of a credential who can present it |
| **I2I** | 4 | Issuer-to-Issuee -- edge operator requiring the current ACDC's Issuer to be the Issuee of the target ACDC. Default for targeted ACDCs. |
| **IPEX** | 9 | Issuance and Presentation Exchange -- six-message non-normative baseline protocol for credential transfer |
| **Issuee** | 8 | AID to whom a targeted credential is issued |
| **Issuer** | 8 | AID that creates and signs a credential |
| **KEL** | 1 | Key Event Log -- immutable log of key management events for an AID |
| **Metadata ACDC** | 5 | A special case of Private ACDC with an empty `u` field (not absent, not high-entropy), used for pre-disclosure negotiation. Has a different SAID than the actual credential. |
| **Most Compact Form** | 3 | The unique representation obtained by depth-first recursive compaction of all sections to SAIDs. Its SAID is what the Issuer signs. |
| **NI2I** | 4 | Not-Issuer-to-Issuee -- edge operator that removes/nullifies the I2I requirement. Default for untargeted ACDCs. |
| **NOT** | 4 | Unary edge operator that inverts the validation truthiness of the far (target) node |
| **Operator** | 4 | Constraint on the relationship between edge source issuer and target issuee (I2I, NI2I, DI2I, NOT) or aggregation logic (AND, OR, WAVG) |
| **Proof of Disclosure** | 6 | Discloser's commitment to the specific disclosed variant, fulfilling a prior IPEX step promise |
| **Proof of Issuance** | 6 | Issuer's signature on the most compact form SAID, verifiable against issuer's key state. A single signature covers all schema-authorized variants. |
| **Registry** | 7 | TEL instance grouping related credentials under common governance |
| **Rule** | 4 | Machine-readable Ricardian contract governing credential use |
| **SAD** | 2 | Self-Addressing Data -- any structure whose `d` field is the SAID of that structure |
| **SAID** | 2 | Self-Addressing Identifier -- CESR-qualified digest embedded in the data it digests |
| **Schema** | 2 | JSON Schema whose `$id` is its SAID; serves as the credential's type identifier |
| **Seal** | 1 | Digest or event reference in a KEL that anchors external data to key state |
| **Selective Disclosure** | 6 | Revealing individual attributes from an aggregated credential with inclusion proofs |
| **TEL** | 7 | Transaction Event Log -- append-only log tracking credential state (issued/revoked) |
| **Validator** | 8 | Verifier that additionally applies domain-specific business rules |
| **Verifier** | 8 | Party that cryptographically validates a presented credential |
| **WAVG** | 4 | Weighted Average -- m-ary edge-group operator that computes a weighted average over edge truthiness values using each edge's `w` (weight) field |

---

## Appendix B: Implementation Guidance

### Making Invalid States Unrepresentable

An implementation SHOULD use its type system to enforce variant constraints at
construction time:

- A `PrivateCredential` type that REQUIRES a nonce parameter
- A `TargetedCredential` type that REQUIRES an issuee AID
- An `AggregatedCredential` type that REQUIRES an AggregateSection and PROHIBITS an AttributeSection
- A `SelectiveDisclosure` operation that ONLY accepts `AggregatedCredential`
- A `MetadataACDC` type that REQUIRES an empty `u` field and allows empty/absent attribute section

### Builder Pattern

Construction of credentials should be guided by a builder that enforces the
constraint matrix:

```
CredentialBuilder
  .schema(said)                    -- REQUIRED (Layer 2)
  .issuer(aid)                     -- REQUIRED (Layer 1)
  .visibility(Private)             -- selects variant dimension 1 (Layer 5)
  .targeting(Targeted(issuee_aid)) -- selects variant dimension 2 (Layer 5)
  .attribute_mode(Aggregated)      -- selects variant dimension 3 (Layer 5)
  .attributes([...])               -- adds claims (Layer 4)
  .edges([...])                    -- adds graph links (Layer 4)
  .rules([...])                    -- adds legal terms (Layer 4)
  .registry(registry)              -- binds to lifecycle (Layer 7)
  .build()                         -- validates, computes most compact form SAID, produces typed credential
```

Each method narrows the type, so that `.attribute_mode(Aggregated)` changes the
return type such that `.selective_disclosure()` becomes available on the result.

### Disclosure Composition

```
DisclosurePolicy
  .reveal_section(Attributes)      -- expand attribute section
  .compact_section(Rules)          -- keep rules as SAID
  .selective_reveal(["score"])     -- for aggregated credentials
  .require_agreement(rule_said)    -- contractual protection
  .build()                        -- validates compatibility with credential variant
```

### Verification Pipeline

Verification should be a composable pipeline where each step can independently
succeed or fail:

```
VerificationPipeline
  .check_said_integrity()          -- Layer 2
  .check_schema_validation()       -- Layer 2
  .check_proof_of_issuance()       -- Layer 6 (signature on most compact form SAID)
  .check_signature(key_state)      -- Layer 1
  .check_credential_state(tel)     -- Layer 7
  .check_bulk_issuance(aggregate)  -- Layer 7 (if bulk-issued)
  .check_edges(graph)              -- Layer 10
  .check_disclosure_proofs()       -- Layer 6
  .check_contractual_chain()       -- Layer 6
  .apply_business_rules(policy)    -- Layer 8 (Validator)
  .result()                        -- aggregated VerificationResult
```

### Developer Persona Map

The key DX insight: a dev building an issuer touches Core + TEL. A wallet dev
touches Core + Disclosure + IPEX. A verifier dev touches Core + Verification.
Nobody needs all five at once.

| Persona | Specs Needed |
|---------|-------------|
| **Issuer developer** | [Core](acdc-core.md) + [TEL](acdc-tel.md) |
| **Wallet / holder developer** | [Core](acdc-core.md) + [Disclosure](acdc-disclosure.md) + [IPEX](acdc-ipex.md) |
| **Verifier developer** | [Core](acdc-core.md) + [Verification](acdc-verification.md) |
| **Full-stack / framework** | All specs |
