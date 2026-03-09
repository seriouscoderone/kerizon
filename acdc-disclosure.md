# ACDC Disclosure Specification

**Version:** 0.4.1-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** [ACDC Core](acdc-core.md) (credential structure, sections, variants, SAID)
**Related specs:** [Verification](acdc-verification.md), [IPEX](acdc-ipex.md)

---

Disclosure is the central innovation of ACDC. It is NOT "sending some fields
and omitting others." It is a **typed, verifiable transformation** from one
credential representation to another, where the transformation itself carries
cryptographic proof.

---

## 1. Proof of Issuance vs Proof of Disclosure

Every credential presentation requires TWO distinct proofs:

**Proof of Issuance:**
- The Issuer's signature on the SAID of the most compact form of the credential.
- Verifiable against the Issuer's key state at the time of the anchoring KEL event.
- Required for ANY disclosure of any variant.
- Because the most compact form SAID is the root of the credential's hash tree,
  a single signature provides Proof of Issuance for ANY schema-authorized variant.

**Proof of Disclosure:**
- The Discloser's commitment to the specific disclosed variant.
- Fulfills the promise made in a prior IPEX step (e.g., the Offer).
- Proves that the disclosed content matches what was previously committed to.
- **Implementation note:** There is no separate "proof of disclosure" data
  structure. In IPEX, the proof is implicit -- the Discloser signs the grant
  message containing the specific credential variant (with its unique
  serialization and SAID path through the hash tree). The grant message itself
  is signed by the Discloser's current key state. The act of sending a signed
  grant with a specific variant IS the proof of disclosure.

The different variants of a credential form a hash tree. The most compact form
SAID is the root. Different disclosure levels correspond to different paths
through this tree. The Issuer signs the root once; verification of any variant
walks from the disclosed sections up to the root.

---

## 2. Disclosure Primitive: CompactTransform

The atomic disclosure operation is replacing an expanded section with its SAID
(compacting) or providing an expanded section to match a known SAID (expanding).

```
CompactTransform:
  compact(section: SAD) -> SAID
  expand(said: SAID, section: SAD) -> Result  -- verifies section.d == said
```

All other disclosure mechanisms are compositions of CompactTransform.

---

## 3. Full Disclosure

Reveal the entire credential with all sections expanded.

```
FullDisclosure:
  disclose(credential: Credential) -> ExpandedCredential
  -- All sections in expanded form
  -- Verifier can see and validate everything
  -- REQUIRES: discloser possesses all expanded sections
  -- REQUIRES: Proof of Issuance (issuer's signature on most compact form SAID)
  -- REQUIRES: Proof of Disclosure (discloser's commitment to this variant)
```

**Dependencies:** CompactTransform (expand all)

---

## 4. Compact Disclosure

Reveal the credential with one or more sections in compact form (SAID only).

```
CompactDisclosure:
  disclose(
    credential: Credential,
    reveal: Set<SectionName>,         -- sections to expand
    withhold: Set<SectionName>        -- sections to keep as SAID
  ) -> PartiallyExpandedCredential

  -- Verifier can confirm withheld sections exist (via SAID)
  -- but cannot see their content
```

**Dependencies:** CompactTransform, credential structure

---

## 5. Partial Disclosure

A specific application of compact disclosure where the discloser reveals a
subset of sections. The verifier can confirm the overall credential integrity
(top-level SAID) while only seeing selected sections.

```
PartialDisclosure:
  disclose(
    credential: Credential,
    sections_to_reveal: Set<SectionName>
  ) -> PartialCredential

  -- sections_to_reveal are expanded
  -- all other sections are compacted to SAIDs
  -- top-level SAID still verifiable
```

**Dependencies:** CompactDisclosure

### Nested Partial Disclosure

Partial disclosure extends hierarchically. When a section contains nested blocks
(each with its own `d` and `u` fields), disclosure can be controlled at different
nesting levels:

```
NestedPartialDisclosure:
  -- Each nested block is independently SAIDed and may have its own UUID
  -- A tree of data blocks can be selectively disclosed at any level
  -- Parent block SAIDs commit to child block SAIDs
  -- Discloser can reveal depth N while compacting depth N+1
```

This enables fine-grained disclosure of hierarchically structured attributes
without requiring the Aggregated attribute mode.

---

## 6. Selective Disclosure

Reveal individual attributes from an aggregated credential. This is only
possible with credentials using the Aggregate attribute mode (`A` field).

```
SelectiveDisclosure:
  disclose(
    credential: AggregatedCredential,
    attributes_to_reveal: Set<AttributeLabel>
  ) -> SelectivePresentation

  -- Returns:
  --   1. The compact credential (with A = AGID)
  --   2. The expanded attribute blocks for revealed attributes
  --   3. Inclusion proofs (all attribute SAIDs for AGID recomputation)

InclusionProof:
  all_attribute_saids: List<SAID>     -- ordered list of ALL attribute SAIDs
  revealed_attributes: Map<Label, AttributeBlock>
  -- Verifier recomputes: AGID = digest(concat(all_attribute_saids))
  -- Verifier confirms revealed attribute SAIDs appear in the list
```

**Dependencies:** AggregateSection, CompactTransform, SAID

**Critical constraint:** Selective disclosure REQUIRES the Aggregated attribute
mode. An Attributed credential cannot do per-field selective disclosure -- it
is all-or-nothing at the attribute section level.

---

## 7. Graduated Disclosure

A progressive revelation protocol where disclosure increases over multiple
exchanges. Each step reveals strictly more than the previous step.

```
GraduatedDisclosure:
  levels: OrderedList<DisclosureLevel>

  -- Typical progression:
  --   Level 0: Metadata ACDC (empty u, sections compacted or absent)
  --   Level 1: Schema + rules revealed (what type, what terms)
  --   Level 2: Partial attribute disclosure (some claims visible)
  --   Level 3: Full disclosure (everything expanded)

DisclosureLevel:
  ordinal: Natural                    -- strictly increasing
  sections_revealed: Set<SectionName>
  attributes_revealed: Set<AttributeLabel>?  -- for aggregated credentials

  -- INVARIANT: level[n].revealed is a subset of level[n+1].revealed
  -- Each level is a superset of the previous
```

**Dependencies:** PartialDisclosure, SelectiveDisclosure, credential variant

---

## 8. Contractually Protected Disclosure

Disclosure governed by Ricardian contracts in the Rule section. The discloser
requires the disclosee to agree to contractual terms before receiving credential
content.

This implements **chain-link confidentiality**: each link in the disclosure
chain is bound by the same (or stricter) contractual obligations.

```
ContractuallyProtectedDisclosure:
  rule_section: RuleSection           -- the terms
  disclosure_chain: List<ChainLink>   -- provenance of disclosure

ChainLink:
  discloser: AID
  disclosee: AID
  terms_agreed: SAID                  -- SAID of the rule section agreed to
  agreement_proof: Signature          -- disclosee's signature on the terms

  -- INVARIANT: each link's terms MUST be equal to or stricter than
  --            the previous link's terms
```

**Dependencies:** RuleSection, disclosure chain verification, KERI signatures

---

## 9. Contingent Disclosure

A special case of Contractually Protected Disclosure where a contingency clause
in the Rule section obligates a party to make a disclosure when specified
conditions are met. This enables **latent accountability**.

```
ContingentDisclosure:
  contingency_clause: Rule            -- defines the triggering condition
  obligated_party: AID               -- party who must disclose upon trigger
  escrowed_credential: Credential    -- the credential to be disclosed

  -- Example: an escrow agent holds a credential containing PII.
  -- The contingency clause states: upon evidence of contractual breach,
  -- the escrow agent MUST disclose the PII credential to the injured party.
  -- Until the condition is met, the credential remains undisclosed.
```

**Dependencies:** ContractuallyProtectedDisclosure, RuleSection

---

## 10. Metadata Disclosure

Using a Metadata ACDC for pre-disclosure negotiation. This is a functional
pattern distinct from the Metadata ACDC variant itself.

```
MetadataDisclosure:
  metadata_acdc: MetadataACDC         -- the negotiation credential (empty u)

  -- The Discloser presents a Metadata ACDC during an IPEX Offer.
  -- The Disclosee evaluates the schema, rules, and structure
  -- WITHOUT being able to correlate to the actual credential's SAID.
  -- If terms are acceptable, the Disclosee sends Agree.
  -- The Discloser then Grants the actual credential.
  -- The Metadata ACDC SAID != the actual credential SAID (different u values).
```

**Dependencies:** MetadataACDC (Core spec, Section 8.5), IPEX Offer ([IPEX spec](acdc-ipex.md))

---

## 11. Disclosure as a Composable Type

All disclosure mechanisms compose. A single presentation may combine:
- Partial disclosure (reveal attributes, compact rules)
- Selective disclosure (reveal only some attributes from an aggregate)
- Contractual protection (require agreement to terms)

```
DisclosurePolicy:
  section_policies: Map<SectionName, SectionDisclosurePolicy>
  contractual: ContractualTerms?

SectionDisclosurePolicy:
  Compact                             -- SAID only
  | Full                              -- entire section expanded
  | Selective(reveal: Set<Label>)     -- specific attributes (aggregate mode only)
```
