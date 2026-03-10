# ACDC Conceptual Architecture Specification

**Version:** 0.4.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification of ACDC domain concepts, their relationships, dependencies, and composition rules. Intended as the blueprint for any clean implementation of the ACDC protocol.
**Normative basis:** ACDC specification, KERI specification, CESR specification

---

## Specification Documents

The ACDC conceptual architecture is organized into focused, self-contained specs.
Each document can be read independently given its stated dependencies.

| Document | Scope |
|----------|-------|
| [ACDC Core](acdc-core.md) | Design principles, dependency graph, CESR/KERI layers, content addressing, credential structure, sections, and variants |
| [ACDC Disclosure](acdc-disclosure.md) | Proof of Issuance/Disclosure, compact/partial/selective/graduated/contractual/contingent disclosure |
| [ACDC TEL](acdc-tel.md) | Registry, TEL events (v1 and v2), credential state machine, blinded state, bulk issuance |
| [ACDC Verification](acdc-verification.md) | Roles (Issuer, Issuee, Holder, Discloser, Disclosee, Verifier, Validator), verification pipeline, escrow model |
| [ACDC IPEX](acdc-ipex.md) | Issuance and Presentation Exchange protocol: message types, state machine, disclosure integration |
| [ACDC Appendix](acdc-appendix.md) | Credential graphs, composition rules, invariants, dependency matrix, glossary, implementation guidance |

### Developer Persona Map

Not every developer needs every spec:

| Persona | Start With |
|---------|-----------|
| **Issuer developer** | [Core](acdc-core.md) + [TEL](acdc-tel.md) |
| **Wallet / holder developer** | [Core](acdc-core.md) + [Disclosure](acdc-disclosure.md) + [IPEX](acdc-ipex.md) |
| **Verifier developer** | [Core](acdc-core.md) + [Verification](acdc-verification.md) |
| **Full-stack / framework** | All specs |
