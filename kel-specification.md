# KEL: Key Event Log Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification for the Key Event Log (KEL), the append-only cryptographic event log at the heart of KERI. Defines both the wire-format protocol mechanics and high-level developer abstractions that hide field-level plumbing behind concept-level APIs.
**Normative basis:** [KERI Specification](https://trustoverip.github.io/kswg-keri-specification/), [CESR Specification](https://trustoverip.github.io/kswg-cesr-specification/)
**Cross-checked against:** keripy reference implementation (`eventing.py`, `serdering.py`, `coring.py`, `basing.py`)

---

## Specification Documents

The KEL specification is organized into four focused documents, connected by
two interface boundaries.

```
                    ┌─────────────────────┐
                    │    kel-api           │  builders, views, workflows
                    │  "how do I use it?"  │
                    └─────────┬───────────┘
                              │ uses
                    ┌─────────▼───────────┐
                    │   kel-engine         │  Kevery, escrow, dispatch,
                    │  "event ingestion"   │  first-seen, duplicity, cues
                    └─────────┬───────────┘
                              │ interface: KeyStateProvider
                    ┌─────────▼───────────┐
                    │   kel-core           │  events, key state, Kever,
                    │  "what KERI is"      │  witnesses, delegation
                    └─────────┬───────────┘
                              │ interface: Primitives
                    ┌─────────▼───────────┐
                    │  kel-crypto          │  Verfer, Diger, Siger, Cigar,
                    │  "crypto toolkit"    │  Tholder, SAID, serialization
                    └─────────────────────┘
```

| Document | Layers | Scope |
|----------|--------|-------|
| [KEL Crypto](kel-crypto.md) | L0 + L1 | CESR primitives, thresholds, serialization, SAID, signature verification |
| [KEL Core](kel-core.md) | L2 + L3 + L4 + L5 | Event types, key state, witnessing, delegation, recovery |
| [KEL Engine](kel-engine.md) | L6 + L7 | Kevery, event dispatch, escrow, duplicity, first-seen ordering, cues |
| [KEL API](kel-api.md) | L8 + Appendices | Builders, KeyState view, verification pipeline, storage, invariants, examples |

### Interface Boundaries

**`Primitives`** (between Crypto and Core): Core doesn't care *how* you sign
or hash, just that you can. This is what cesride/cesr-ts already provides.

**`KeyStateProvider`** (between Core and Engine): The engine asks "what's the
current key state for this AID?" without knowing how state was derived. This
is also the interface that TEL and ACDC depend on — they never import the
engine, they import key state.

### Developer Persona Map

Not every developer needs every spec:

| Persona | Start With |
|---------|-----------|
| **Controller dev** (creating AIDs, signing) | Crypto + Core + API |
| **Verifier / infrastructure dev** (replaying KELs, running witnesses) | Crypto + Core + Engine |
| **Integration dev** (connecting ACDC/TEL) | Crypto + Core (via `KeyStateProvider` interface) |
| **Full-stack / framework** | All specs |
