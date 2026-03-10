# EXN: Exchange Protocol Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification of the KERI peer-to-peer Exchange (EXN) protocol for structured application-layer messaging between KERI controllers
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation (`src/keri/peer/exchanging.py`)

---

## 1. Purpose and Scope

The Exchange protocol (EXN) is the application-layer peer-to-peer messaging protocol in the KERI ecosystem. EXN provides structured message exchange between KERI controllers with cryptographic authentication, route-based handler dispatch, and chained conversation support.

EXN is NOT a transport protocol. Transport is handled by infrastructure components such as mailboxes and message routers. EXN defines the message format, verification rules, and dispatch semantics that operate above the transport layer.

The protocol stack relationship is:

| Layer | Component | Responsibility |
|-------|-----------|----------------|
| Application | EXN | Structured peer-to-peer exchanges, IPEX, multisig coordination |
| Transport | Mailbox / Message routing | Store-and-forward delivery of CESR streams |
| Protocol | KERI messages | Events, receipts, queries, replies |
| Encoding | CESR | Composable event streaming representation |

EXN messages carry IPEX credential exchanges, multisig coordination proposals, delegation requests, OOBI exchange requests, challenge-response interactions, and message forwarding directives. All of these are consumers of the EXN protocol via route-based handler registration.

## 2. Terminology

**Exchange Message (EXN):** A Self-Addressing Data (SAD) structure with message type `exn` that carries an application-layer payload between KERI controllers.

**Exchange Inception (XIP):** A SAD structure with message type `xip` that initiates an exchange session. Defined only for KERI protocol version 2.

**Route:** A `/`-delimited path string in the `r` field that determines which handler processes the message (e.g., `/ipex/grant`, `/multisig/rot`).

**Handler:** A registered processor object that implements `handle()` (and optionally `verify()`) for a specific route string.

**Pathed CESR Stream (PTD):** A CESR-encoded attachment qualified with a Pather that indicates which field of the embedded event section (`e`) the attachment belongs to.

**ESSR (Encrypted CESR Stream):** An encrypted CESR stream attached to an EXN message, verified against a digest seal in the event's embedded section.

**Transferable Signature Group (TSG):** A quadruple of (Prefixer, Seqner, Saider, [Sigers]) linking indexed signatures to a specific establishment event of a transferable AID.

**Cigar:** An unindexed signature coupled with its non-transferable verification key.

**Lead:** In a multisig context, the signer of an EXN message whose signing key has the lowest index among all signers. The lead is responsible for transmission of the EXN to its recipient.

## 3. EXN Message Structure

### 3.1 Field Definitions

An EXN message is a SAD (Self-Addressing Data structure) with a SAID-based digest in its `d` field. The field layout differs between KERI protocol version 1 and version 2.

#### Version 1 Fields

| Field | Label | Type | Description |
|-------|-------|------|-------------|
| Version | `v` | string | Protocol version string (e.g., `KERI10JSON00011c_`) |
| Type | `t` | string | Message type, always `exn` |
| SAID | `d` | string | Self-addressing identifier (Blake3-256 digest) |
| Sender | `i` | string | qb64 AID of the message sender |
| Recipient prefix | `rp` | string | qb64 AID of the intended recipient (optional, may be empty) |
| Previous | `p` | string | SAID of previous exchange message in a chain (empty string if none) |
| Datetime | `dt` | string | ISO-8601 datetime of message creation |
| Route | `r` | string | `/`-delimited route path for handler dispatch |
| Query/Modifiers | `q` | dict | Modifier parameters analogous to URI query string |
| Attributes | `a` | dict or string | Payload attributes; may be a nested dict or a SAID digest string |
| Embedded | `e` | dict | Embedded KERI event SAD structures with their own SAID in `e.d` |

#### Version 2 Fields

| Field | Label | Type | Description |
|-------|-------|------|-------------|
| Version | `v` | string | Protocol version string |
| Type | `t` | string | Message type, always `exn` |
| SAID | `d` | string | Self-addressing identifier (Blake3-256 digest) |
| Sender | `i` | string | qb64 AID of the message sender |
| Receiver | `ri` | string | qb64 AID of the intended receiver |
| Exchange ID | `x` | string | SAID of exchange inception (`xip`) if any |
| Previous | `p` | string | SAID of previous exchange message in a chain |
| Datetime | `dt` | string | ISO-8601 datetime of message creation |
| Route | `r` | string | `/`-delimited route path for handler dispatch |
| Query/Modifiers | `q` | dict | Modifier parameters |
| Attributes | `a` | dict | Payload attributes; in v2, embedded events are nested inside `a` |

### 3.2 SAID and Self-Addressing

The `d` field contains a SAID computed as a Blake3-256 digest over the serialized message content. The SAID provides a unique, content-bound identifier for each exchange message, enabling:

- Immutable reference to a specific exchange
- Chaining of exchanges via the `p` field
- Database storage keyed by SAID
- Replay detection

During creation, the `d` field is initialized to an empty string, then the serialized form is used to compute the digest which replaces the placeholder.

### 3.3 Exchange Chaining (the `p` Field)

Exchange messages support conversation threading via the `p` (previous) field. When `p` contains the SAID of a prior exchange message, the current message is a response or continuation of that exchange.

Chaining enables multi-step protocols. The IPEX credential exchange protocol is the primary consumer of this mechanism:

```
Apply (p="") --> Offer (p=apply.said) --> Agree (p=offer.said) --> Grant (p=agree.said) --> Admit (p=grant.said)
```

When a message has a non-empty `p` field, the Exchanger records the relationship in the reply index (`erpy` database) mapping the previous SAID to the new message's SAID. This enables lookup of the response to any exchange message.

### 3.4 Exchange Inception (XIP) - Version 2 Only

KERI protocol version 2 introduces the Exchange Inception (`xip`) message type, which establishes a session context for a series of related exchanges.

| Field | Label | Type | Description |
|-------|-------|------|-------------|
| Version | `v` | string | Protocol version string |
| Type | `t` | string | Always `xip` |
| SAID | `d` | string | Self-addressing identifier |
| Nonce | `u` | string | qb64 UUID salty nonce for uniqueness |
| Sender | `i` | string | qb64 AID of session initiator |
| Receiver | `ri` | string | qb64 AID of session receiver |
| Datetime | `dt` | string | ISO-8601 datetime |
| Route | `r` | string | Route for session handler |
| Query | `q` | dict | Session modifiers |
| Attributes | `a` | dict | Session attributes |

Subsequent `exn` messages in the session reference the XIP via the `x` (exchange ID) field.

### 3.5 Embedded Events (the `e` Field)

The `e` field contains embedded KERI event SAD structures. These are opaque to the exchange protocol itself; their content is interpreted by the route-specific handler.

When embedded events are present:

1. Each named entry in the `e` dict is deserialized as a SAD (via `Sadder`).
2. Any CESR attachment bytes following the embedded event's serialized form are extracted.
3. These attachments are wrapped in Pathed Material Couples, prefixed with a `Pather` that encodes the path `["e", <label>]`.
4. The `e` dict receives its own SAID in `e.d`, computed via `Saider.saidify()`.

In version 2, embedded events are placed inside the attributes (`a`) field rather than in a separate `e` field at the top level.

## 4. Route-Based Handler Dispatch

### 4.1 Handler Registration

The `Exchanger` class maintains a route-to-handler mapping. Handlers are registered at initialization time or dynamically via `addHandler()`.

Each handler object MUST have:
- A `resource` attribute containing the route string it handles.
- A `handle(serder, attachments=None, **kwa)` method called after successful signature verification.

Each handler object MAY have:
- A `verify(serder, attachments=None, **kwa)` method called before the event is logged. If `verify()` returns `False`, the event is silently dropped. If the handler has no `verify()` method, verification is skipped (the event is accepted).

Registration enforces uniqueness: attempting to register two handlers for the same route raises a `ValidationError`.

### 4.2 Route Matching

Route matching is exact string equality. The route string from the `r` field of the EXN message is used as a dictionary key to look up the handler. If no handler is registered for the route, the message is silently ignored (the handler variable is `None` and both `verify()` and `handle()` calls are guarded by `AttributeError` exception handlers).

### 4.3 Standard Routes

The following table lists the standard routes defined across the keripy reference implementation:

| Route | Module | Purpose |
|-------|--------|---------|
| `/ipex/apply` | `vc.protocoling` | Apply for an ACDC credential |
| `/ipex/offer` | `vc.protocoling` | Offer a metadata ACDC |
| `/ipex/agree` | `vc.protocoling` | Agree to an ACDC offer |
| `/ipex/grant` | `vc.protocoling` | Disclose (grant) an ACDC credential |
| `/ipex/admit` | `vc.protocoling` | Admit (accept) a credential disclosure |
| `/ipex/spurn` | `vc.protocoling` | Reject an apply, offer, agree, or grant |
| `/multisig/icp` | `app.grouping` | Propose multisig group inception |
| `/multisig/rot` | `app.grouping` | Propose multisig group rotation |
| `/multisig/ixn` | `app.grouping` | Propose multisig group interaction |
| `/multisig/vcp` | `app.grouping` | Propose multisig credential registry inception |
| `/multisig/iss` | `app.grouping` | Propose multisig credential issuance |
| `/multisig/rev` | `app.grouping` | Propose multisig credential revocation |
| `/multisig/exn` | `app.grouping` | Propose multisig exchange message |
| `/multisig/rpy` | `app.grouping` | Propose multisig reply message |
| `/delegate/request` | `app.delegating` | Request delegation approval from delegator |
| `/fwd` | `app.forwarding` | Forward embedded events to a mailbox recipient |
| `/oobis` | `app.oobiing` | Request OOBI resolution |
| `/challenge/response` | `app.challenging` | Respond to a challenge with signed words |

## 5. Signature Verification

When the Exchanger receives an EXN message via `processEvent()`, it performs signature verification before dispatching to the route handler. The verification supports two signing modes.

### 5.1 Transferable Signers (Indexed Signature Groups)

Transferable signers attach Transferable Indexed Signature Groups (TSGs). Each TSG is a quadruple:

```
(Prefixer, Seqner, Saider, [Sigers])
```

Where:
- **Prefixer**: the qb64 AID prefix of the signing controller
- **Seqner**: the sequence number of the signer's establishment event whose keys produced the signatures
- **Saider**: the SAID (digest) of that establishment event
- **[Sigers]**: list of indexed signatures from the signer's keys

Verification steps:

1. **Sender check**: The Prefixer's qb64 MUST match the `i` (sender) field. If it does not, a `MissingSignatureError` is raised.

2. **Kever lookup**: The sender MUST exist in the local key event state (`kevers`) and the kever's sequence number MUST be at least as large as the Seqner's value. If not found, the message is escrowed as a Partially Signed Exchange (PSE) and a query cue is emitted to fetch the sender's key event log.

3. **Signature verification**: The signing keys (verfers) and threshold holder are resolved from the database using the Prefixer, Seqner, and Saider. Each Siger is verified against its corresponding Verfer over the serialized message bytes.

4. **Threshold satisfaction**: The set of valid signature indices MUST satisfy the threshold defined in the signer's establishment event. If the threshold is not met, the message is escrowed as a PSE.

### 5.2 Non-Transferable Signers (Cigar Couples)

Non-transferable signers attach Cigar couples. Each Cigar contains a raw signature and its associated non-transferable verification key (Verfer).

Verification steps:

1. **Sender check**: The Cigar's Verfer qb64 MUST match the `i` (sender) field.
2. **Signature verification**: The Cigar's Verfer verifies the raw signature against the serialized message bytes.

If either check fails, a `MissingSignatureError` is raised.

### 5.3 No Signatures

If neither TSGs nor Cigars are provided, the message is escrowed as a PSE with an empty TSG list, and a `MissingSignatureError` is raised.

### 5.4 Pathed CESR Streams

After signature verification, pathed CESR streams are processed. Each pathed stream is a byte sequence beginning with a Pather (CESR-encoded path). Streams whose path starts with `["e"]` (the embedded events section) are extracted: the `e` prefix is stripped, yielding a sub-path and the remaining attachment bytes.

These extracted `(path, attachment)` pairs are passed to the handler as the `attachments` keyword argument.

### 5.5 ESSR (Encrypted CESR Streams)

If ESSR attachments are present, they are concatenated and passed to the handler as the `essr` keyword argument. When the embedded event section (`e`) is a string rather than a dict, it is treated as a SAID digest of the ESSR content. The Exchanger verifies the digest against the ESSR bytes using a Diger, raising a `ValidationError` on mismatch.

## 6. Message Time Window

The Exchanger enforces a time window for message freshness. The default window is 300 seconds (5 minutes), configurable via the `delta` parameter at Exchanger initialization.

The time window is expressed as a Python `timedelta` and is used primarily in escrow processing rather than initial message acceptance. The `dt` field of the EXN message records the creation timestamp in ISO-8601 format, which can be validated against the current time by handlers or upstream components.

## 7. Escrow Processing

### 7.1 Partially Signed Exchanges (PSE)

When an EXN message cannot be fully verified (missing kever, insufficient signatures, or no signatures at all), it is placed in the Partially Signed Exchange escrow. The escrow stores:

- **`epse`**: The serialized EXN event, keyed by SAID
- **`epsd`**: A Dater recording the escrow entry time, keyed by SAID
- **`esigs`**: Individual Siger values, keyed by (SAID, Prefixer, Seqner, Saider) quadruple
- **`epath`**: Pathed attachment bytes, keyed by SAID

When a message is escrowed, the Exchanger emits a `query` cue to request the sender's key event log, enabling the local system to fetch the missing establishment event.

### 7.2 Escrow Processing Loop

The `processEscrowPartialSigned()` method iterates over all escrowed events and re-attempts `processEvent()` for each:

1. Load the escrowed serder from `epse`.
2. Check the escrow timestamp from `epsd` against the current time.
3. If the escrow age exceeds `TimeoutPSE` (default: 10 seconds), the escrow is stale and the event is removed.
4. Reconstruct TSGs from stored `esigs` entries.
5. Load stored pathed attachments from `epath` and ESSRs from `essrs`.
6. Re-attempt `processEvent()` with the reconstructed data.

On success, the escrow entries are removed. On `MissingSignatureError`, the event remains escrowed for the next cycle. On any other exception, the escrow is removed (the event is permanently dropped).

### 7.3 Timeout and Cleanup

The `TimeoutPSE` class attribute (default: 10 seconds) defines the maximum age of an escrowed exchange before it is discarded. This is distinct from the `ExchangeMessageTimeWindow` (300 seconds), which governs general message freshness.

## 8. Event Logging

After successful signature verification and handler-specific verification (if any), the EXN event is persisted in the exchange event log:

- **`exns`**: The full serialized EXN event, keyed by SAID
- **`esigs`**: Transferable signature groups, keyed by (SAID, Prefixer, Seqner, Saider) quadruple
- **`ecigs`**: Non-transferable Cigar couples, keyed by SAID
- **`epath`**: Pathed attachment bytes, keyed by SAID
- **`essrs`**: ESSR Texter values, keyed by SAID
- **`erpy`**: Reply index mapping previous SAID to response Diger (populated when `p` is non-empty)

A `saved` cue with the event's SAID is emitted after logging, notifying downstream components that the exchange has been accepted and stored.

## 9. Standard Route Registry

### 9.1 IPEX Routes (`/ipex/*`)

The Issuance and Presentation Exchange (IPEX) protocol uses EXN to implement a six-message credential exchange flow. See the ACDC-IPEX specification for details.

| Route | Initiates? | Chains from | Purpose |
|-------|-----------|-------------|---------|
| `/ipex/apply` | Yes | (none) | Request credential issuance |
| `/ipex/offer` | Yes | `apply` | Offer a metadata ACDC |
| `/ipex/agree` | No | `offer` | Accept an offer |
| `/ipex/grant` | Yes | `agree` | Disclose a full ACDC with TEL events |
| `/ipex/admit` | No | `grant` | Acknowledge receipt of credential |
| `/ipex/spurn` | No | `apply`, `offer`, `agree`, `grant` | Reject any prior step |

The IPEX handler implements `verify()` to enforce chaining rules:
- `apply` may only appear with an empty `p` field (it initiates).
- `offer` and `grant` may appear with empty `p` (unsolicited) or chain from their predecessor.
- `agree`, `admit`, and `spurn` MUST chain from a prior message.
- A message that already has a response recorded in `erpy` is rejected (no duplicate responses).

### 9.2 Multisig Routes (`/multisig/*`)

Multisig coordination uses EXN to propose group events to fellow group members. The handler is a simple notification forwarder (Multiplexor) that:

1. Validates the sender is a member of the referenced group.
2. Associates the EXN SAID with the embedded event section's SAID.
3. Notifies the local controller.
4. If the local controller has already approved identical embedded events, parses and processes them with their additional signatures.

Embedded events are the actual KERI events being proposed (inception, rotation, interaction, registry events, etc.).

### 9.3 Delegation Route (`/delegate/request`)

The delegation handler processes requests from a delegate to its delegator for anchoring approval. The payload contains the delegator prefix (`delpre`) and the embedded event requiring approval.

### 9.4 Forward Route (`/fwd`)

The forward handler extracts embedded events from the EXN and stores them in a mailbox for the intended recipient. The `q` (modifiers) field contains:
- `pre`: the qb64 AID of the destination
- `topic`: the topic string for mailbox storage

The mailbox resource key is `{pre}/{topic}`.

### 9.5 OOBI Route (`/oobis`)

The OOBI handler receives a peer-to-peer request to resolve an OOBI URL. It extracts the `oobi` field from the payload, stores it for resolution, and notifies the local controller.

### 9.6 Challenge Route (`/challenge/response`)

The challenge-response handler processes signed word lists. The handler signals the local controller via a transient notification and records the signer's AID against the exchange SAID in the `reps` database for tracking successful challenge completions.

## 10. Relationship to Transport

EXN defines message format and processing semantics but does not specify how messages reach their destination. Transport is the responsibility of:

- **Mailbox infrastructure**: Witnesses and watchers maintain mailboxes (store-and-forward queues) keyed by recipient AID and topic. The `/fwd` route handler stores messages in mailboxes.
- **Direct HTTP/TCP connections**: EXN messages can be sent directly between agents over any reliable transport.
- **Poster/Postman**: The forwarding infrastructure wraps EXN messages in `/fwd` envelopes and delivers them to the recipient's witnesses or agents for mailbox storage.

An EXN message traverses:

```
Sender --> [wrap in /fwd if indirect] --> Witness/Agent mailbox --> Recipient polls mailbox --> Exchanger.processEvent()
```

## 11. Security Considerations

### 11.1 Authentication

Every EXN message MUST be signed by the sender identified in the `i` field. The Exchanger verifies signatures against the sender's current key state (kever). Messages from unknown senders are escrowed pending key event log retrieval.

### 11.2 Replay Protection

The combination of SAID uniqueness and the `dt` timestamp provides replay protection. Each message has a unique content-derived identifier, and handlers may enforce time window constraints.

### 11.3 Signature Threshold

For transferable AIDs, the Exchanger enforces the signature threshold defined in the sender's latest establishment event. This ensures multisig AIDs cannot send exchange messages without meeting their own governance requirements.

### 11.4 ESSR Integrity

When an EXN carries encrypted content via ESSR, the digest of the encrypted stream is embedded in the `e` field as a SAID. The Exchanger verifies this digest before dispatching to the handler, preventing tampering with encrypted content.

### 11.5 Escrow Limits

Partially signed exchanges are automatically discarded after the `TimeoutPSE` window (default: 10 seconds), limiting the window for resource exhaustion attacks via incomplete messages.

## 12. Implementation Notes

### 12.1 Lead Election in Multisig

When a group multisig AID sends an EXN message, only one member (the "lead") transmits the message to the recipient. The lead is the member whose signing key corresponds to the lowest signature index among all signers. This prevents duplicate delivery.

### 12.2 Handler Error Tolerance

The Exchanger wraps both `verify()` and `handle()` calls in `AttributeError` exception handlers. This allows handlers that only implement one of the two methods to function without error. A handler with no `verify()` method implicitly passes verification.

### 12.3 Completion Check

The `complete(said)` method checks whether an exchange message has been successfully processed and stored in the `exns` database. This is used by upstream components to poll for exchange completion.

### 12.4 Message Cloning and Serialization

Two utility functions support message retrieval:
- `cloneMessage(hby, said)`: loads and re-verifies an EXN from the database, returning the serder and nested pathed attachments.
- `serializeMessage(hby, said)`: reconstructs the full CESR stream (event bytes + signature attachments + pathed couples) suitable for retransmission.

### 12.5 Database Keys

Exchange events and their associated data are stored using SAID-based keys:

| Database | Key | Value | Purpose |
|----------|-----|-------|---------|
| `exns` | `(said,)` | SerderKERI | Stored exchange events |
| `esigs` | `(said, pre, sn, dig)` | Siger | Transferable indexed signatures |
| `ecigs` | `(said,)` | (Verfer, Cigar) | Non-transferable signatures |
| `epse` | `(said,)` | SerderKERI | Partially signed escrow |
| `epsd` | `(said,)` | Dater | Escrow timestamp |
| `epath` | `(said,)` | bytes | Pathed attachments |
| `essrs` | `(said,)` | Texter | ESSR encrypted streams |
| `erpy` | `(prev_said,)` | Diger | Reply index (previous to response) |
