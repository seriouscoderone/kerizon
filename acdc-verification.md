# ACDC Verification: Roles and Verification Pipeline

**Version:** 0.4.1-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** [ACDC Core](acdc-core.md), [Disclosure](acdc-disclosure.md), [TEL](acdc-tel.md)
**Related specs:** [IPEX](acdc-ipex.md)

---

Roles define bounded interfaces -- the set of operations a participant can
perform. Each role is identified by an AID and constrained to specific
operations.

---

## 1. Issuer

The AID that creates and signs the credential.

```
Issuer:
  aid: AID

  -- Operations:
  create_credential(
    variant: CredentialVariant,
    schema: Schema,
    attributes: AttributeSection | AggregateSection,
    edges: EdgeSection?,
    rules: RuleSection?,
    registry: Registry
  ) -> SignedCredential

  revoke(credential: SAID, registry: Registry) -> RevocationEvent

  bulk_issue(
    credentials: List<Credential>,
    registry: Registry
  ) -> BulkIssuanceEvent

  -- Constraints:
  --   MUST control the signing keys for aid (via KEL)
  --   MUST anchor issuance/revocation to own KEL
  --   MUST NOT modify a credential after issuance (immutability)
  --   Signs the SAID of the most compact form (Proof of Issuance)
```

---

## 2. Issuee

The AID to whom a targeted credential is issued. Optional -- untargeted
credentials have no issuee.

```
Issuee:
  aid: AID

  -- Properties:
  --   Identified in the attribute section's `i` field
  --   Credential is bound to this AID
  --   Typically (but not necessarily) the initial Holder
```

---

## 3. Holder

The party in possession of a credential who can present it to others. The Holder
MAY or MAY NOT be the Issuee.

```
Holder:
  aid: AID
  credentials: CredentialStore        -- credentials in possession

  -- Operations:
  present(
    credential: Credential,
    disclosure_policy: DisclosurePolicy,
    to: AID                           -- the verifier
  ) -> Presentation

  prepare_selective_disclosure(
    credential: AggregatedCredential,
    reveal: Set<AttributeLabel>
  ) -> SelectivePresentation

  initiate_graduated_disclosure(
    credential: Credential,
    levels: List<DisclosureLevel>
  ) -> GraduatedDisclosureSession

  -- Constraints:
  --   For targeted credentials, Holder SHOULD be the Issuee
  --   (but protocol does not enforce this -- it is a trust decision)
```

---

## 4. Discloser

The party that reveals credential content. Often the Holder, but may be a
delegated party. The Discloser must provide BOTH Proof of Issuance and
Proof of Disclosure.

```
Discloser:
  aid: AID

  -- Operations:
  disclose(
    credential: Credential,
    policy: DisclosurePolicy,
    disclosee: AID
  ) -> DisclosedPresentation

  -- The Discloser transforms a credential according to a DisclosurePolicy
  -- and provides it to a Disclosee with appropriate proofs:
  --   1. Proof of Issuance: Issuer's signature on the most compact form SAID
  --   2. Proof of Disclosure: Discloser's commitment to the disclosed variant
```

---

## 5. Disclosee

The party receiving a disclosed credential. Takes on obligations if contractually
protected disclosure is used.

```
Disclosee:
  aid: AID

  -- Operations:
  receive(presentation: DisclosedPresentation) -> Result
  agree_to_terms(rules: RuleSection) -> SignedAgreement  -- for contractual disclosure

  -- Constraints:
  --   If contractually protected, MUST sign agreement before receiving content
  --   Agreement becomes a ChainLink in the disclosure chain
```

---

## 6. Verifier

The party that cryptographically validates a presented credential.

```
Verifier:
  aid: AID

  -- Operations:
  verify(presentation: Presentation) -> VerificationResult

  -- Verification steps (all required):
  --   1. SAID integrity: recompute SAID of each expanded section, confirm match
  --   2. Schema validation: validate expanded sections against credential schema
  --   3. Proof of Issuance: verify Issuer's signature on the most compact form SAID
  --      against the Issuer's key state (replaying KEL)
  --   4. Key state verification: replay issuer's KEL to confirm signing keys
  --   5. Credential state: check TEL for issuance (not revoked)
  --   6. Edge verification: if edges present, recursively verify chained credentials
  --   7. Operator verification: confirm edge operators (I2I, NI2I, DI2I) are satisfied
  --      NOTE: DI2I is spec-defined but not yet implemented in keripy
  --      (verifying.py raises NotImplementedError). Implementations should
  --      expect DI2I to require full KERI delegation chain verification.
  --   8. Expiry check: if datetime field present, confirm not expired
  --   9. Disclosure proof: for selective disclosure, verify inclusion proofs
  --   10. Contractual chain: if contractually protected, verify disclosure chain
  --   11. Bulk issuance: if bulk-issued, verify blinded SAID inclusion in aggregate
  --   12. Proof of Disclosure: verify Discloser's commitment to the disclosed variant

VerificationResult:
  credential_said: SAID
  issuer: AID
  issuer_key_state: KeyState          -- at time of signing
  credential_state: Issued | Revoked
  schema_valid: bool
  proof_of_issuance_valid: bool
  proof_of_disclosure_valid: bool
  edges_valid: Map<EdgeLabel, VerificationResult>?  -- recursive
  disclosure_valid: bool
  errors: List<VerificationError>?
```

### 6.1 Verification Escrow Model

When a credential cannot be fully verified because dependent data is not yet
available, the Verifier places the credential into an escrow and emits a cue
requesting the missing data. The credential is re-processed when the missing
data arrives.

**Escrow types:**

| Escrow | Abbreviation | Trigger | Resolution |
|--------|-------------|---------|------------|
| Missing Registry Escrow | MRE | Registry TEL not resolved, credential state not found, or credential state expired | Registry TEL becomes available or credential state refreshed |
| Missing Schema Escrow | MSE | Schema not resolved from cache | Schema becomes available |
| Missing Chain Escrow | MCE | Edge target credential not available or chain state expired | Target credential received and verified |

**Verification pipeline ordering:**

The Verifier processes a credential through the following steps in order. A
failure at any step triggers the corresponding escrow:

1. **Registry resolution** -- look up the registry TEL by `regid`. If not found, escrow to MRE.
2. **Credential state lookup** -- query the registry for the credential's current state. If state is missing or expired, escrow to MRE.
3. **Revocation check** -- if the credential state indicates revocation (`rev`/`brv`), log the revoked state (no escrow; revoked credentials are still saved).
4. **Schema validation** -- resolve the schema by SAID and validate the credential against it. If schema is not in cache, escrow to MSE.
5. **Edge chain verification** -- for each edge, verify the target credential's chain. If a target credential is missing or its state is expired, escrow to MCE per edge.
6. **Save verified credential** -- store the credential and emit a "saved" cue.

This ordering ensures that the cheapest checks (registry existence) are
performed first, avoiding unnecessary schema resolution or chain verification
for credentials whose registry is not yet available.

---

## 7. Validator

A Verifier that additionally applies domain-specific business rules beyond
cryptographic verification.

```
Validator:
  extends Verifier

  -- Additional operations:
  apply_policy(
    verification: VerificationResult,
    business_rules: PolicySet
  ) -> ValidationResult

  -- Examples of business rules:
  --   Credential must be less than 30 days old
  --   Issuer must be in an approved issuer list
  --   Specific schema SAIDs are accepted
  --   Minimum disclosure level required
```
