# ACDC IPEX: Issuance and Presentation Exchange Protocol

**Version:** 0.4.1-draft
**Status:** Draft
**Part of:** [ACDC Conceptual Architecture](acdc-conceptual-architecture.md)
**Dependencies:** [ACDC Core](acdc-core.md), [Disclosure](acdc-disclosure.md), [Verification](acdc-verification.md), [TEL](acdc-tel.md)

---

The Issuance and Presentation Exchange (IPEX) protocol governs how credentials
are requested, offered, and transferred between parties. It is a six-message
protocol with a rejection path.

**Non-normative status:** The ACDC specification explicitly states that the IPEX
section is **non-normative** and provides a **baseline** exchange protocol.
Implementations MAY use alternative exchange protocols provided they satisfy the
same cryptographic commitment requirements (Proof of Issuance and Proof of
Disclosure).

---

## 1. IPEX Message Types

```
     Disclosee                           Discloser
         |                                   |
         |---- Apply (request credential) -->|
         |                                   |
         |<---- Offer (metadata ACDC) -------|
         |                                   |
         |---- Agree (accept terms) -------->|
         |                                   |
         |<---- Grant (full/partial ACDC) ---|
         |                                   |
         |---- Admit (acknowledge receipt) ->|
         |                                   |
         |---- Spurn (reject at any step) -->|
         |<---- Spurn (reject at any step) --|
```

---

## 2. Message Semantics

```
Apply:
  -- Requests a credential (used in BOTH issuance and presentation contexts)
  -- In issuance context: Issuee requests a credential from an Issuer
  -- In presentation context: Verifier requests a credential from a Holder/Discloser
  -- Contains: desired schema, desired attributes, proposed terms
  -- Initiates the exchange
  -- Does NOT require prior credential possession

Offer:
  -- Discloser proposes a credential (metadata-level disclosure)
  -- Contains: Metadata ACDC (u field present but empty; sections compacted or absent)
  -- Disclosee can evaluate type, schema, rules WITHOUT seeing content
  -- Metadata ACDC SAID differs from actual credential SAID (prevents correlation)
  -- May be unsolicited (Discloser initiates) or response to Apply

Agree:
  -- Disclosee accepts the offered terms
  -- Contains: reference to the Offer being accepted
  -- For contractually protected disclosure: includes signed agreement
  -- MUST reference a prior Offer

Grant:
  -- Discloser reveals credential content
  -- Contains: ACDC at the agreed disclosure level
  -- Includes: TEL events proving issuance status
  -- Includes: CESR attachments (signatures, anchors)
  -- Includes: Proof of Issuance (Issuer's signature on most compact form SAID)
  -- May be unsolicited or response to Agree/Apply

Admit:
  -- Disclosee confirms receipt and successful verification
  -- Contains: reference to the Grant being acknowledged
  -- MUST reference a prior Grant

Spurn:
  -- Either party rejects the exchange at any point
  -- Contains: reference to the message being rejected, reason
  -- Terminates the exchange
```

---

## 3. IPEX State Machine

**Strict transition rules:** Within any exchange sequence, steps CANNOT be
skipped. The code enforces a strict `PreviousRoutes` mapping
(source: `protocoling.py:14-22`) that validates each message's predecessor.

**Transition table:**

| From | To | Required? | Notes |
|------|----|-----------|-------|
| Apply | Offer | Required | Cannot skip |
| Offer | Agree | Required | Cannot skip |
| Agree | Grant | Required | Cannot skip |
| Grant | Admit | Required | Cannot skip |
| Apply/Offer/Agree/Grant | Spurn | Always | Terminates exchange |

```
                    +----------+
                    |  Start   |
                    +----+-----+
                         |
              +----------+----------+
              |          |          |
              v          v          v
         +--------+ +--------+ +--------+
         | Apply  | | Offer  | | Grant  |  (three valid entry points)
         +---+----+ +---+----+ +---+----+
             |          |          |
             v          v          v
         +--------+ +--------+ +--------+
         | Offer  | | Agree  | | Admit  |
         +---+----+ +---+----+ +--------+
             |          |
             v          v
         +--------+ +--------+
         | Agree  | | Grant  |
         +---+----+ +---+----+
             |          |
             v          v
         +--------+ +--------+
         | Grant  | | Admit  |
         +---+----+ +--------+
             |
             v
         +--------+
         | Admit  |
         +--------+

  (Spurn can occur at any state, terminating the exchange)
```

**Valid exchange sequences (different starting points, NOT skipped steps):**
1. `Apply -> Offer -> Agree -> Grant -> Admit` (full negotiation)
2. `Offer -> Agree -> Grant -> Admit` (unsolicited offer)
3. `Grant -> Admit` (direct grant, no negotiation)
4. Any of the above, terminated by `Spurn` at any step

The four sequences represent different **starting points** for an exchange
(e.g., start at Grant for simple presentation), NOT skipped steps within a
sequence. Once a sequence begins, each step must proceed to the next in strict
order -- there is no mechanism to jump from Apply directly to Grant, or from
Offer directly to Grant.

> **Implementation guidance:** Implementations MUST support at minimum the full
> negotiation sequence (1). They SHOULD support the abbreviated sequences (2-3)
> as well, since ecosystem requirements may demand direct Grant or unsolicited
> Offer flows. Implementations that restrict the state machine to only the full
> negotiation path will be unable to participate in ecosystems that use the
> abbreviated sequences defined by the specification.

---

## 4. IPEX and Disclosure Integration

Each IPEX message carries a specific disclosure level:

| Message | Disclosure Level |
|---------|-----------------|
| Apply | None (request only) |
| Offer | Metadata disclosure (Metadata ACDC with empty `u`, sections compacted/absent) |
| Agree | None (acceptance only) |
| Grant | Configurable: full, partial, selective, or graduated |
| Admit | None (acknowledgment only) |
| Spurn | None (rejection only) |

The Grant message's disclosure level is determined by:
1. The DisclosurePolicy agreed upon during Offer/Agree
2. The credential's variant (aggregated credentials enable selective disclosure)
3. Contractual terms in the Rule section
