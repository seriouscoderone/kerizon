# KERI Standalone Mailbox Service Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-03-03

---

## 1. Purpose and Scope

This document specifies a **standalone Mailbox Service** for the KERI (Key Event Receipt Infrastructure) protocol ecosystem. The Mailbox is an authenticated, multi-tenant, append-only message relay that enables asynchronous communication between KERI controllers.

### 1.1 Problem Statement

KERI controllers (entities managing cryptographic identifiers) are not always online. When Controller A needs to send a message to Controller B (a receipt, credential, multisig coordination request, etc.), Controller B may be offline or unreachable. The Mailbox Service acts as a store-and-forward relay — accepting messages on behalf of offline controllers and serving them when the controller polls.

### 1.2 Scope

This specification covers:

- The Mailbox Service as an **independent, deployable service** — fully separated from KERI witness infrastructure
- All interfaces: message ingress (write), message egress (read), provisioning, and authentication
- KERI protocol dependencies required for implementation
- Data model, retention semantics, and multi-tenancy

This specification does **not** cover:

- KERI witness behavior (event receipting, TOAD, KEL validation)
- KERI event processing (Kevery, Tevery, escrows)
- Credential or exchange semantics (the mailbox treats all payloads as opaque bytes)
- Specific transport bindings (SSE, WebSocket, etc.) — these are implementation choices

### 1.3 Design Principles

1. **Payload opacity.** The mailbox never parses, validates, or interprets message content. Messages are opaque byte sequences.
2. **Log semantics.** Messages are appended to a topic log and never dequeued. Consumers track their own position via cursors.
3. **Minimal KERI surface.** The mailbox depends on approximately 5% of the KERI protocol stack — only what is needed for authentication and provisioning.
4. **Separation from witnesses.** Witnesses are trust infrastructure (they receipt events and contribute to accountability via TOAD). Mailboxes are service infrastructure (they relay bytes). These are orthogonal concerns.
5. **Multi-tenant by default.** A single mailbox instance serves multiple AIDs.

---

## 2. Terminology

### 2.1 KERI Concepts

| Term | Definition |
|------|-----------|
| **AID** | Autonomic Identifier. A self-certifying identifier cryptographically bound to a set of key pairs. The fundamental unit of identity in KERI. Represented as a CESR-encoded string (e.g., `EAbcde...`). |
| **Controller** | The entity that controls an AID by holding the corresponding private keys. A controller authors KERI events and signs messages. |
| **KEL** | Key Event Log. The append-only, hash-chained sequence of key events (inception, rotation, interaction) that defines the authoritative history of an AID. |
| **Key State** | The current cryptographic state of an AID: its active signing keys, rotation keys, thresholds, witnesses, and configuration. Derived from the latest establishment event in the KEL. |
| **Witness** | An entity designated by a controller (in inception/rotation events) to receive, verify, receipt (sign), and store key events. Witnesses contribute to the TOAD (Threshold of Accountable Duplicity) and are trust infrastructure. |
| **CESR** | Composable Event Streaming Representation. A self-describing, composable encoding format used throughout KERI for primitives, events, and attachments. |
| **Verfer** | A CESR-qualified public verification key. Used to verify signatures. |
| **OOBI** | Out-of-Band Introduction. An untrusted `(URL, AID)` tuple that provides a discovery mechanism. OOBIs are resolved and then cryptographically verified via KERI. |
| **Indirect Mode** | KERI's asynchronous operational mode, where controllers communicate via intermediary infrastructure (witnesses, mailboxes) rather than direct connections. The mailbox enables indirect mode. |
| **KERIA** | KERI Agent — a multi-tenant cloud agent service that hosts identifiers and acts as a proxy for Signify edge clients. KERIA may act as a mailbox for its managed identifiers. |
| **Signify** | A protocol and client library for "signing at the edge." Signify clients hold private keys locally and communicate with a KERIA cloud agent. The KERIA agent may poll mailboxes on behalf of the Signify client. |
| **Endpoint Authorization** | A signed KERI reply message (`/end/role/add` or `/end/role/cut`) by which a controller cryptographically authorizes or deauthorizes a service endpoint for a specific role. |

### 2.2 Mailbox-Specific Terms

| Term | Definition |
|------|-----------|
| **Sender** | The AID that authored and signed a message being delivered to the mailbox. |
| **Recipient** | The AID whose mailbox the message is addressed to. Messages are stored per-recipient. |
| **Poller** | The entity retrieving messages from a mailbox. Usually the recipient themselves, but may be a proxy (e.g., KERIA polling on behalf of a Signify client). |
| **Topic** | A named channel within a recipient's mailbox (e.g., `/receipt`, `/multisig`, `/credential`). Messages are appended to topics independently. |
| **TopicAddress** | A composite key: `(recipient AID, topic name)`. Uniquely identifies a message stream within the mailbox. |
| **Ordinal** | A monotonically increasing integer assigned to each message within a topic. Ordinals are scoped to a single `TopicAddress` — they provide ordering within a topic, not globally. |
| **Cursor** | A `(TopicAddress, ordinal)` pair representing a poller's position in a topic log. The poller stores cursors locally and advances them as messages are consumed. |
| **Provisioning** | The process by which a recipient AID authorizes the mailbox service to accept and store messages on its behalf. |

---

## 3. Architecture Overview

### 3.1 System Context

```
   Sender Controllers              Mailbox Service              Pollers
   ────────────────                ─────────────────            ───────

   Controller A ─── /fwd ───┐     ┌───────────────┐
   Controller B ─── /fwd ───┤     │               │     ┌─── Recipient X (direct)
   Witness W    ─── receipt ─┼────▶│   Ingress     │     │
   Delegator D  ─── delegate─┤     │   (authn +    │     │
   Issuer I     ─── credential┘     │    store)     │     │
                                   │               │     │
                                   │───────────────│     │
                                   │               │◀────┤
                                   │   Egress      │     │
                                   │   (authn +    │     └─── KERIA Agent (proxy
                                   │    stream)    │           for Signify client)
                                   │               │
                                   │───────────────│
                                   │               │
                                   │  Provisioner  │◀──── /end/role/add from
                                   │  (authz)      │      Recipient X
                                   │               │
                                   │───────────────│
                                   │               │
                                   │  Key State    │◀──── Witness/Watcher query
                                   │  Resolver     │      (external lookup)
                                   │  (cache)      │
                                   └───────────────┘
```

### 3.2 Separation from Witnesses

In the current keripy reference implementation, witnesses and mailboxes are co-located in a single process. This specification defines them as separate services. The distinction:

| Concern | Witness | Mailbox |
|---------|---------|---------|
| **Role** | Trust infrastructure | Service infrastructure |
| **Declared in** | KEL (inception/rotation events, `b` field) | Endpoint authorization (signed reply, out-of-band to KEL) |
| **Core duty** | Receipt (sign) first-seen key events | Store-and-forward opaque message bytes |
| **Processes payloads** | Yes — verifies signatures, checks sequence numbers, detects duplicity | No — payloads are opaque bytes |
| **Contributes to TOAD** | Yes | No |
| **KERI stack required** | Full (Kevery, event validation, KEL storage) | Minimal (signature verification, key state lookup) |
| **Changed via** | Key event (rotation required) | Endpoint authorization reply (no rotation needed) |

A controller may declare 3 witnesses for TOAD purposes and 1 mailbox for message relay. These are independent decisions.

### 3.3 Component Architecture

The Mailbox Service consists of five components:

```
MailboxService
├── MailboxStore           Pure storage — append-only topic logs
├── MailboxIngress         Write endpoint — accepts messages from senders
├── MailboxEgress          Read endpoint — streams messages to pollers
├── MailboxProvisioner     Authorization — manages which AIDs are served
└── KeyStateResolver       External dependency — resolves current AID key state
```

Each component is described in detail in Section 5.

---

## 4. Data Model

### 4.1 Value Objects

#### TopicAddress

A composite addressing key that identifies a message stream.

```
TopicAddress {
    recipient: AID       // The AID whose mailbox this belongs to
    topic: string        // The topic channel name (e.g., "/receipt")
}
```

**Serialization:** `"{recipient}/{topic}"` — e.g., `"EAbcde.../receipt"`

**Constraints:**
- `recipient` must be a valid CESR-encoded AID
- `topic` must start with `/` and contain only alphanumeric characters, hyphens, and underscores
- `topic` must not be empty

#### Cursor

A poller's position within a topic log.

```
Cursor {
    topic: TopicAddress
    ordinal: uint64      // The next ordinal to read (last-seen + 1)
}
```

**Ownership:** Cursors are owned and persisted by the **poller**, not the mailbox. The mailbox has no knowledge of cursor state.

#### Envelope

A stored message.

```
Envelope {
    payload: bytes       // Opaque message content (never parsed by mailbox)
    digest: bytes        // Content-addressed hash (Blake3-256 of payload)
}
```

**Properties:**
- Content-addressing provides natural deduplication — if two senders deliver the same message, it is stored once
- The digest serves as the storage key in the message store
- The mailbox never inspects or deserializes `payload`

### 4.2 Storage Structure

The mailbox uses two logical stores:

**Topic Index** — maps `(TopicAddress, ordinal)` to a message digest:

```
(recipient, topic, ordinal) → digest
```

- Ordinals are assigned by the mailbox on write, monotonically increasing per TopicAddress
- Ordinals are scoped to a single TopicAddress — topic `/receipt` and topic `/multisig` have independent ordinal sequences

**Message Store** — maps digest to payload bytes:

```
digest → payload
```

- Content-addressed: the key is the Blake3-256 hash of the payload
- Multiple topic index entries may reference the same digest (deduplication)
- Messages are immutable once stored

### 4.3 Topic Names

Topics represent categories of KERI protocol messages. The following topics are used in the current KERI ecosystem:

| Topic | Content | Producers | Purpose |
|-------|---------|-----------|---------|
| `/receipt` | Witness receipt events (signed endorsements of key events) | Witnesses | Deliver event receipts to controller |
| `/reply` | Peer-to-peer exchange responses | Any controller | Direct reply to an exchange message |
| `/replay` | Historical KEL segments | Any controller | Re-send of past key events |
| `/delegate` | Delegation requests and approvals | Delegators, Delegates | Delegation coordination |
| `/multisig` | Multisig coordination messages (signature contributions, rotation proposals, join requests) | Multisig participants | Multi-party signing coordination |
| `/credential` | IPEX credential exchange messages (grant, admit, offer, agree, spurn) | Credential issuers, holders, verifiers | Credential issuance and presentation |
| `/challenge` | Authentication challenge-response words | Any controller | Mutual authentication between controllers |
| `/oobi` | OOBI resolution requests and responses | Any controller | Out-of-band identifier introduction |

**Extensibility:** Topic names are conventions, not a closed set. Implementations may define additional topics. The mailbox treats all topics identically — it does not assign semantic meaning to topic names.

---

## 5. Component Interfaces

### 5.1 MailboxStore

Pure storage component. No KERI awareness. No network I/O. No authentication.

```
interface MailboxStore {

    // ── Write ──────────────────────────────────────────────────

    store(topic: TopicAddress, payload: bytes) → StoreResult
        // Computes Blake3-256 digest of payload.
        // Appends digest to topic index with next ordinal.
        // Stores payload in message store (idempotent if digest exists).
        // Returns: { ordinal: uint64, digest: bytes, isNew: bool }

    // ── Read ───────────────────────────────────────────────────

    retrieve(topic: TopicAddress, fromOrdinal: uint64)
        → Iterator<(ordinal: uint64, payload: bytes)>
        // Returns a lazy iterator of messages for the given topic,
        // starting at fromOrdinal (inclusive).
        // Ordering: ascending by ordinal.
        // If fromOrdinal exceeds the latest ordinal, returns empty iterator.

    retrieveMulti(
        recipient: AID,
        topicCursors: Map<string, uint64>
    ) → Iterator<(topic: string, ordinal: uint64, payload: bytes)>
        // Retrieves messages across multiple topics for a single recipient.
        // Each entry in topicCursors maps a topic name to the starting ordinal.
        // Iterates across topics in round-robin or interleaved fashion.
        // This is the common case — pollers almost always query multiple topics.

    // ── Tenant Lifecycle ───────────────────────────────────────

    provision(recipient: AID) → void
        // Prepares storage for a new recipient AID.
        // Idempotent — safe to call multiple times.

    deprovision(recipient: AID) → void
        // Marks a recipient as deprovisioned.
        // Implementation may defer actual data deletion to retention policy.

    isProvisioned(recipient: AID) → bool
        // Returns true if the recipient AID is currently provisioned.

    // ── Retention ──────────────────────────────────────────────

    trim(topic: TopicAddress, beforeOrdinal: uint64) → uint64
        // Removes topic index entries with ordinal < beforeOrdinal.
        // Orphaned message store entries (no remaining index references)
        // may be cleaned up immediately or deferred.
        // Returns: number of entries removed.

    trimByAge(recipient: AID, maxAge: Duration) → uint64
        // Removes all topic index entries older than maxAge for a recipient.
        // Returns: number of entries removed.
}
```

**Implementation notes:**
- The store is an append-only log. Messages are never modified after storage.
- `retrieve` and `retrieveMulti` are non-destructive reads — they do not advance any server-side cursor or delete messages.
- Content-addressed storage means `store()` is idempotent for identical payloads.
- The `trim` and `trimByAge` methods are for operator-managed retention, not consumer-driven dequeuing.

### 5.2 MailboxIngress

Accepts messages from senders. Authenticates senders. Stores messages via MailboxStore.

```
interface MailboxIngress {

    submit(
        sender: AID,
        recipient: AID,
        topic: string,
        payload: bytes,
        authorization: bytes
    ) → SubmitResult
        // Validates:
        //   1. Recipient is provisioned on this mailbox
        //   2. Sender authentication (see Section 6.2)
        //   3. Topic name is well-formed
        // On success: stores payload via MailboxStore.store()
        // Returns: { ordinal: uint64, digest: bytes } or error

    // Error cases:
    //   RecipientNotProvisioned  — AID not authorized on this mailbox
    //   SenderAuthFailed         — signature verification failed
    //   InvalidTopic             — malformed topic name
    //   PayloadTooLarge          — exceeds size limit (implementation-defined)
}
```

**Wire protocol mapping (example):**

An HTTP-based implementation might accept a `POST /submit` with a CESR-encoded `/fwd` exchange envelope. The ingress handler:

1. Parses the outer `/fwd` envelope to extract `sender`, `recipient`, and `topic` from the envelope metadata
2. Extracts the inner payload as opaque bytes (does not parse it)
3. Verifies the sender's signature on the envelope
4. Calls `MailboxStore.store()`

The `/fwd` envelope format (from the current KERI implementation):

```json
{
    "v": "KERI10JSON...",
    "t": "exn",
    "r": "/fwd",
    "q": {
        "pre": "<recipient AID>",
        "topic": "<topic name>"
    },
    "e": {
        "<embedded payload>": "..."
    }
}
```

The mailbox parses the outer structure (`r`, `q.pre`, `q.topic`) but treats `e` as opaque bytes.

### 5.3 MailboxEgress

Serves messages to authenticated pollers. Streams from MailboxStore.

```
interface MailboxEgress {

    poll(
        poller: AID,
        recipient: AID,
        credentials: Credentials,
        topicCursors: Map<string, uint64>
    ) → Stream<EgressEvent>
        // Validates:
        //   1. Recipient is provisioned on this mailbox
        //   2. Poller is authorized to read recipient's mailbox (see Section 6.1)
        // On success: streams messages via MailboxStore.retrieveMulti()
        // Stream continues until timeout or client disconnect.

    // EgressEvent:
    //   { topic: string, ordinal: uint64, payload: bytes }

    // Error cases:
    //   RecipientNotProvisioned  — AID not authorized on this mailbox
    //   PollerAuthFailed         — authentication failed
    //   PollerNotAuthorized      — poller is not the recipient or authorized proxy
}
```

**Poller authorization rules:**

- If `poller == recipient`: always authorized (controller reading own mailbox)
- If `poller != recipient`: poller must present proof of proxy authorization (e.g., KERIA agent authorized via endpoint role designation by the recipient). See Section 6.1.

**Streaming behavior:**

- The egress returns all messages matching `topicCursors` that are currently stored
- After delivering stored messages, the stream may remain open for a configurable timeout period, delivering new messages as they arrive (real-time tailing)
- If no new messages arrive within the timeout, the stream closes and the poller reconnects with updated cursors
- The timeout duration is implementation-defined (keripy uses 30 seconds)

**Transport options:** The egress interface is transport-agnostic. Implementations may use:

- SSE (Server-Sent Events) — current keripy approach, unidirectional server-to-client
- WebSockets — bidirectional, lower latency
- HTTP long-polling — simpler, works behind restrictive firewalls
- gRPC server streaming — structured, high performance

### 5.4 MailboxProvisioner

Manages which AIDs the mailbox is authorized to serve. Processes KERI endpoint authorization messages.

```
interface MailboxProvisioner {

    processAuthorization(reply: bytes) → ProvisionResult
        // Parses a signed KERI reply message with route /end/role/add
        // or /end/role/cut.
        //
        // For /end/role/add:
        //   1. Extracts { cid: AID, role: "mailbox", eid: AID } from reply
        //   2. Verifies cid == the AID authorizing the mailbox
        //   3. Verifies eid == this mailbox's AID
        //   4. Verifies role == "mailbox"
        //   5. Verifies signature against cid's current key state
        //   6. On success: provisions cid in MailboxStore
        //
        // For /end/role/cut:
        //   Same validation, then deprovisions cid.
        //
        // Returns: Provisioned(cid) | Deprovisioned(cid) | error

    isAuthorized(recipient: AID) → bool
        // Returns true if recipient has a valid, active authorization.

    listAuthorized() → List<AID>
        // Returns all currently provisioned AIDs.
}
```

**Authorization reply format:**

The KERI `/end/role/add` reply message has the following structure:

```json
{
    "v": "KERI10JSON...",
    "t": "rpy",
    "d": "<SAID of this reply>",
    "dt": "2026-03-03T12:00:00.000000+00:00",
    "r": "/end/role/add",
    "a": {
        "cid": "<controller AID authorizing the endpoint>",
        "role": "mailbox",
        "eid": "<this mailbox service's AID>"
    }
}
```

This message is signed by the controller (`cid`) using their current signing keys. The mailbox verifies the signature against the controller's current key state (resolved via KeyStateResolver).

**The mailbox's own AID:** The mailbox service itself must have an AID (non-transferable is sufficient). This AID is the `eid` in endpoint authorization replies. Controllers reference this AID when designating the mailbox.

### 5.5 KeyStateResolver

The single external KERI dependency. Resolves the current key state for an AID.

```
interface KeyStateResolver {

    resolve(aid: AID) → KeyState?
        // Returns the current key state for the given AID, or null if unknown.
        //
        // KeyState contains:
        //   - currentKeys: List<Verfer>    (current signing public keys)
        //   - currentThreshold: Threshold  (signing threshold — may be weighted)
        //   - witnessAids: List<AID>       (declared witnesses)
        //   - sequenceNumber: uint64       (latest establishment event sn)
        //   - digest: bytes                (latest establishment event digest)

    refresh(aid: AID) → KeyState?
        // Forces a fresh resolution, bypassing cache.
        // Used after receiving a rotation notification.
}
```

**Resolution strategies (implementation chooses one or more):**

1. **Query witnesses directly.** Send a KERI key state query (`qry` with `r="ksn"`) to the AID's declared witnesses. Requires network access to witness endpoints.

2. **Query a watcher.** If the mailbox operator runs a watcher, query it for cached key state. Lower latency, single point of contact.

3. **Cache with TTL.** Cache resolved key state with a time-to-live. Refresh on cache miss or TTL expiry. Practical for most deployments.

4. **Accept key state on provisioning.** When processing `/end/role/add`, the controller may include their current KEL or key state notice alongside the authorization reply. The mailbox caches it.

**What KeyStateResolver does NOT do:**
- It does not maintain a full KEL
- It does not validate event chains or detect duplicity
- It does not participate in witness receipting or TOAD
- It only answers: "What are the current signing keys for AID X?"

---

## 6. Authentication

### 6.1 Poller Authentication (Egress)

Before serving messages, the mailbox must verify the poller controls the recipient AID (or is an authorized proxy).

**Challenge-response protocol:**

```
Poller                              Mailbox
  │                                    │
  ├── poll(poller, recipient, ...)────▶│
  │                                    │
  │◀── Challenge(nonce) ──────────────┤
  │                                    │
  ├── Response(sign(nonce, pollerKey))─▶│
  │                                    │
  │    Mailbox verifies signature       │
  │    against recipient's current      │
  │    keys via KeyStateResolver        │
  │                                    │
  │◀── Stream<EgressEvent> ───────────┤
```

**Verification steps:**

1. Mailbox generates a cryptographically random nonce
2. Poller signs the nonce with the private key corresponding to the recipient's AID (or the poller's AID if acting as proxy)
3. Mailbox resolves the recipient's current key state via `KeyStateResolver.resolve(recipient)`
4. Mailbox verifies the signature against the resolved public keys and signing threshold
5. On success: begins streaming messages

**Proxy authorization (KERIA case):**

When `poller != recipient`, the poller must additionally prove it is authorized to act on behalf of the recipient. This is established via an endpoint authorization: the recipient must have issued an `/end/role/add` reply designating the poller's AID as an `agent` role for the recipient. The mailbox checks this authorization before serving messages.

**Session caching:** After successful authentication, the mailbox may cache the authentication result for the duration of the polling session (e.g., the SSE connection lifetime), avoiding re-authentication on every request.

### 6.2 Sender Authentication (Ingress)

Verifying senders is **recommended but optional**. The mailbox may operate in two modes:

**Authenticated mode (recommended for production):**

The mailbox verifies the signature on the `/fwd` exchange envelope. This prevents:
- Spam: unauthorized senders filling a recipient's mailbox
- Impersonation: messages claiming to be from an AID the sender doesn't control

Verification: the mailbox resolves the sender's key state via `KeyStateResolver.resolve(sender)` and verifies the envelope signature.

**Open mode (acceptable for trusted networks):**

The mailbox accepts any well-formed `/fwd` envelope without verifying the sender's signature. The recipient's own KERI stack will verify message authenticity when it processes the payload. This is acceptable in closed deployments where all participants are trusted, but inappropriate for public-facing mailboxes.

### 6.3 KERI Cryptographic Primitives Required

The mailbox needs these CESR/KERI primitives for authentication:

| Primitive | Purpose | CESR Code |
|-----------|---------|-----------|
| **Verfer** | Public verification key (Ed25519, ECDSA, etc.) | `D` (Ed25519), `1AAA` (ECDSA 256k1), etc. |
| **Cigar** | Unindexed signature (for non-transferable AIDs) | `0B` (Ed25519), etc. |
| **Siger** | Indexed signature (for transferable AIDs with multi-key thresholds) | `AA` (Ed25519 index 0), etc. |
| **Diger** | Digest (Blake3-256 for content addressing) | `E` (Blake3-256) |
| **Prefixer** | AID prefix (self-certifying identifier) | `D` (basic), `E` (self-addressing) |

The mailbox must be able to:

1. Parse CESR-encoded signatures from message attachments
2. Extract the public key (`Verfer`) from resolved key state
3. Verify a signature against a message digest and public key
4. Evaluate signing thresholds (simple numeric or weighted fractional)

---

## 7. Message Flow

### 7.1 Provisioning Flow

```
Controller                          Mailbox Service
    │                                      │
    │  1. Create /end/role/add reply       │
    │     { cid: myAID,                    │
    │       role: "mailbox",               │
    │       eid: mailboxAID }              │
    │     Sign with current keys           │
    │                                      │
    ├── POST /authorize ──────────────────▶│
    │                                      │  2. Parse reply
    │                                      │  3. Resolve myAID key state
    │                                      │  4. Verify signature
    │                                      │  5. Provision myAID in store
    │◀── 200 OK ──────────────────────────┤
    │                                      │
    │  6. Publish OOBI for mailbox:        │
    │     http://mbx.example.com/oobi/     │
    │       {myAID}/mailbox/{mailboxAID}   │
    │                                      │
```

### 7.2 Message Delivery Flow (Sender to Mailbox)

```
Sender                              Mailbox Service
    │                                      │
    │  1. Wrap payload in /fwd envelope:   │
    │     { r: "/fwd",                     │
    │       q: { pre: recipientAID,        │
    │            topic: "/credential" },   │
    │       e: { <opaque payload> } }      │
    │     Sign envelope                    │
    │                                      │
    ├── POST /submit ─────────────────────▶│
    │                                      │  2. Parse envelope (outer only)
    │                                      │  3. Verify sender signature (if authn mode)
    │                                      │  4. Check recipient is provisioned
    │                                      │  5. Extract payload bytes
    │                                      │  6. store(TopicAddress(recipient, topic), payload)
    │◀── 200 OK { ordinal, digest } ──────┤
    │                                      │
```

### 7.3 Message Retrieval Flow (Poller from Mailbox)

```
Poller (Controller)                 Mailbox Service
    │                                      │
    │  1. Construct query with cursors:    │
    │     { recipient: myAID,              │
    │       topics: {                      │
    │         "/receipt": 42,              │
    │         "/multisig": 7,              │
    │         "/credential": 0 } }         │
    │                                      │
    ├── POST /poll ───────────────────────▶│
    │                                      │  2. Authenticate poller (Section 6.1)
    │                                      │  3. retrieveMulti(recipient, topicCursors)
    │                                      │
    │◀── Stream<EgressEvent> ─────────────┤
    │    { topic: "/receipt",    on: 42,   │
    │      payload: <bytes> }              │
    │    { topic: "/receipt",    on: 43,   │
    │      payload: <bytes> }              │
    │    { topic: "/credential", on: 0,    │
    │      payload: <bytes> }              │
    │    ...                               │
    │                                      │
    │  4. Client advances local cursors:   │
    │     "/receipt": 44                   │
    │     "/credential": 1                 │
    │                                      │
    │  5. Stream times out or closes       │
    │  6. Reconnect with updated cursors   │
    │                                      │
```

### 7.4 Message Routing Decision (by sender's router)

When a controller wants to send a message to a recipient, the routing decision happens client-side:

```
Sender's MailboxRouter:

    1. Look up recipient's endpoint authorizations
    2. Check for explicit mailbox endpoints (Roles.mailbox)
       → If found: submit to the standalone mailbox service (Section 7.2)
    3. Fallback: check for witnesses (Roles.witness)
       → If found: wrap in /fwd and send to a randomly selected witness
          (legacy behavior — witness-as-mailbox)
    4. If neither found: Undeliverable
```

The MailboxRouter is a **client-side** component, not part of the mailbox service itself. It is included here for completeness because it determines how messages reach the mailbox.

---

## 8. Log Semantics and Retention

### 8.1 Append-Only Log

The mailbox topic is an **append-only log**, not a queue:

- Messages are **never dequeued** on read
- Messages are **never modified** after storage
- Multiple pollers can read the same messages independently
- Each poller maintains its own cursor position locally

This design choice is deliberate:

1. **Idempotent consumption.** KERI messages are cryptographically self-verifying. Receiving the same message twice is harmless — the recipient's Kevery/Exchanger detects duplicates.
2. **Multiple pollers.** A controller may poll from multiple devices, or a KERIA proxy and the controller may both poll. If reads were destructive, the second poller would miss messages.
3. **Cursor independence.** Each `(poller, recipient)` pair tracks its own progress. The mailbox has no global "consumed" state.
4. **Crash recovery.** If a poller crashes before processing a message, it re-reads from its last persisted cursor. No messages are lost.

### 8.2 Cursor Management

Cursors are **client-side state**. The mailbox service does not store, manage, or advance cursors.

**Poller responsibilities:**
- Persist cursors locally (e.g., in a database keyed by `(poller AID, mailbox AID, recipient AID)`)
- Advance cursors after successfully processing each message
- On reconnect, provide current cursor positions in the poll request

**Cursor per-source tracking:**

If a recipient uses multiple mailboxes (or legacy witness-as-mailbox), cursors are tracked per source. Example:

```
Recipient: EAbcde...
  Mailbox MBX1:
    /receipt: ordinal 42
    /multisig: ordinal 7
  Witness WIT1 (legacy):
    /receipt: ordinal 15
    /reply: ordinal 3
  Witness WIT2 (legacy):
    /receipt: ordinal 22
```

### 8.3 Retention Policy

Since messages are never dequeued, the mailbox must implement a retention policy to bound storage growth. Retention is an **operational concern**, not a protocol concern.

**Recommended strategies:**

| Strategy | Description | Trade-offs |
|----------|-------------|------------|
| **Time-based** | Remove messages older than N days | Simple; risk of removing messages a slow poller hasn't seen |
| **Size-based** | Cap total storage per recipient | Predictable costs; may lose recent messages under burst |
| **Ordinal-based** | Keep only the last N messages per topic | Simple; predictable per-topic bounds |
| **Operator-managed** | Expose `trim()` and `trimByAge()` for manual or cron-based cleanup | Maximum flexibility; requires operational tooling |

**No cursor-based retention:** The mailbox cannot trim based on consumer progress because it does not track cursors. If cursor-aware retention is desired, a separate "retention coordinator" could query pollers for their cursor positions and invoke `trim()` accordingly, but this is outside the scope of the core mailbox service.

**Retention and deduplication:** The message store uses content-addressed storage. A message referenced by multiple topic index entries is stored once. Trimming a topic index entry only removes the index pointer; the message blob is eligible for garbage collection only when no remaining index entries reference it.

---

## 9. Multi-Tenancy

### 9.1 Tenant Model

A single mailbox instance serves multiple recipient AIDs. Each AID is a **tenant**.

**Isolation guarantees:**

- **Data isolation.** A poller authenticated as AID X cannot read messages for AID Y. The egress enforces authentication per-recipient.
- **Storage isolation.** Topic logs for different recipients are independent. Ordinal sequences do not interact.
- **No cross-tenant visibility.** The mailbox does not expose a list of provisioned AIDs to any tenant. `listAuthorized()` is an operator/admin function.

### 9.2 Provisioning Lifecycle

```
                    /end/role/add
    Pending ─────────────────────▶ Active
                                     │
                                     │ /end/role/cut
                                     ▼
                                  Deprovisioned
                                     │
                                     │ retention policy
                                     ▼
                                  Data purged
```

- **Pending → Active:** Controller submits signed `/end/role/add` reply. Mailbox verifies and provisions.
- **Active → Deprovisioned:** Controller submits signed `/end/role/cut` reply. Mailbox stops accepting new messages but existing messages remain available for retrieval (grace period).
- **Deprovisioned → Purged:** After a retention period, all stored messages for the AID are deleted.

---

## 10. KERI Protocol Dependencies

### 10.1 Dependency Summary

The mailbox service requires a **minimal subset** of the KERI protocol stack:

```
Full KERI stack (e.g., witness):
┌────────────────────────────────────────────────────────┐
│  Kevery    Tevery    Revery    Exchanger    Parser     │
│  KEL validation    receipting    TOAD    escrows       │
│  Full CESR codec   Serder   event processing          │
│  LMDB with full basing schema                         │
│  Credential chains   ACDC    TEL                      │
└────────────────────────────────────────────────────────┘

Mailbox protocol surface:
┌────────────────────────────────────────────────────────┐
│  Verfer (signature verification)                      │
│  Diger (Blake3-256 content hashing)                   │
│  Prefixer (AID parsing)                               │
│  Siger / Cigar (signature parsing)                    │
│  Sadder / Serder (envelope parsing — outer only)      │
│  Threshold evaluation (simple + weighted fractional)  │
│  /end/role/add reply parsing                          │
│  /fwd envelope outer structure parsing                │
│  Key state resolution (external query + cache)        │
│  Challenge-response protocol                          │
│  CESR stream attachment parsing (for signatures)      │
└────────────────────────────────────────────────────────┘
```

### 10.2 What the Mailbox Does NOT Need

| Component | Why Not Needed |
|-----------|---------------|
| **Kevery** (Key Event Verifier) | The mailbox does not validate key events. It stores them as opaque bytes. |
| **Tevery** (Transaction Event Verifier) | No TEL (Transaction Event Log) processing. |
| **Revery** (Reply Verifier) | Only the `/end/role/add` reply is parsed; general reply processing is not needed. |
| **Parser** (full CESR stream parser) | Only envelope-level parsing is needed, not recursive message processing. |
| **Exchanger** (exchange message handler) | The mailbox does not process exchange semantics — it stores payloads. |
| **KEL storage** | No Key Event Logs are maintained. Only current key state is cached. |
| **Escrow processing** | No out-of-order event handling. |
| **ACDC/credential parsing** | Credentials are opaque payloads. |
| **Duplicity detection** | Not a trust function — that is witness/watcher responsibility. |

### 10.3 The Mailbox's Own AID

The mailbox service must have its own AID for:

1. **Identification.** The `eid` field in `/end/role/add` replies references the mailbox's AID.
2. **OOBI generation.** The mailbox publishes OOBIs in the form: `http://mbx.example.com/oobi/{recipient}/mailbox/{mailboxAID}`
3. **Authentication.** The mailbox may sign challenge responses when other components query it.

**Recommendation:** Use a **non-transferable AID** (derived directly from a public key, no rotation capability). The mailbox's key does not protect sensitive data — it only identifies the service endpoint. If the key is compromised, the operator generates a new AID and controllers re-provision. This keeps the mailbox's own key management trivial.

---

## 11. Discovery (OOBI Integration)

### 11.1 Mailbox OOBI Format

After a controller provisions a standalone mailbox, they publish an OOBI:

```
http://mbx.example.com/oobi/{controllerAID}/mailbox/{mailboxAID}
```

This tells senders: "To deliver messages to `{controllerAID}`, submit them to the mailbox service at `mbx.example.com`, which is operated by `{mailboxAID}`."

**Comparison with existing OOBI types:**

| OOBI Type | Format | Purpose |
|-----------|--------|---------|
| Witness | `http://host/oobi/{cid}/witness/{witAID}` | KEL retrieval + implicit mailbox (legacy) |
| Agent | `http://host/oobi/{cid}/agent/{agentAID}` | KERIA cloud agent endpoint |
| **Mailbox** | `http://host/oobi/{cid}/mailbox/{mbxAID}` | **Dedicated message relay** |

### 11.2 OOBI Resolution by Senders

When a sender wants to deliver a message to a recipient:

1. Resolve the recipient's OOBIs (received out-of-band: QR code, message, directory, etc.)
2. Look for a `/mailbox/` role OOBI → use the standalone mailbox endpoint
3. If no mailbox OOBI found, fall back to `/witness/` OOBIs (legacy behavior)
4. Submit the message to the discovered endpoint

---

## 12. Security Considerations

### 12.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Unauthorized reading** — attacker reads messages for an AID they don't control | Poller authentication via challenge-response (Section 6.1) |
| **Spam / mailbox stuffing** — attacker fills a recipient's mailbox with junk | Sender authentication (Section 6.2) + per-recipient storage quotas |
| **Impersonation** — attacker claims to be a sender they're not | Signature verification on `/fwd` envelopes |
| **Replay attacks** — attacker re-submits previously seen messages | Content-addressed dedup (same payload = same digest = no-op) |
| **Enumeration** — attacker probes which AIDs are served | Mailbox returns identical errors for non-provisioned and provisioned AIDs on auth failure |
| **Key compromise of mailbox AID** — attacker obtains mailbox's private key | Mailbox AID is non-transferable; compromise only affects mailbox identity, not stored message confidentiality (messages are KERI-signed by senders, not encrypted by mailbox) |
| **Man-in-the-middle** — attacker intercepts polling connections | TLS required for all transport. KERI signatures on messages provide end-to-end integrity regardless of transport. |
| **Denial of service** — attacker overwhelms the mailbox | Rate limiting, per-AID quotas, standard DoS mitigations |

### 12.2 Confidentiality

The mailbox stores messages **in cleartext** (as submitted). Message confidentiality is **not** a mailbox concern:

- KERI protocol messages (key events, receipts) are public by design
- If confidential exchange is needed, it is handled at the application layer via encrypted CESR streams (ESSR) before submission to the mailbox
- The mailbox operator can read stored messages — this is acceptable because messages are cryptographically signed by their senders, and the mailbox cannot forge or modify them

### 12.3 Integrity

Message integrity is guaranteed by KERI's cryptographic properties, not by the mailbox:

- All KERI messages are signed by their senders
- Recipients verify signatures using the sender's key state (resolved from the sender's KEL)
- The mailbox cannot modify a message without invalidating the sender's signature
- Content-addressed storage (Blake3-256) provides tamper detection at the storage layer

---

## 13. Deployment Considerations

### 13.1 Standalone Deployment

```
┌──────────────────────────┐
│   Standalone Mailbox     │
│                          │
│   ┌──────────────────┐   │
│   │  HTTP/HTTPS      │   │
│   │  Server          │   │◀── TLS termination
│   └──────┬───────────┘   │
│          │               │
│   ┌──────▼───────────┐   │
│   │  Ingress +       │   │
│   │  Egress +        │   │
│   │  Provisioner     │   │
│   └──────┬───────────┘   │
│          │               │
│   ┌──────▼───────────┐   │
│   │  MailboxStore    │   │
│   │  (LMDB/SQLite/   │   │
│   │   DynamoDB/etc)  │   │
│   └──────────────────┘   │
│                          │
│   ┌──────────────────┐   │
│   │  KeyStateResolver│   │──▶ queries witnesses/watchers
│   │  (cache + query) │   │
│   └──────────────────┘   │
└──────────────────────────┘
```

### 13.2 Co-located with Witness (backward compatibility)

For backward compatibility, the mailbox may be co-located with a witness in the same process. In this configuration:

- The witness handles event receipting and KEL duties
- The mailbox handles message relay duties
- They share a network address but are logically separate components
- Messages are stored in the mailbox, not in the witness KERL

### 13.3 Co-located with KERIA

KERIA cloud agents may embed a mailbox for their managed identifiers. In this configuration:

- KERIA automatically provisions mailboxes for identifiers it manages
- Signify clients poll via KERIA's existing API (KERIA acts as both the mailbox and the poller proxy)
- External senders submit to KERIA's HTTP endpoint

---

## 14. Implementation Checklist

### 14.1 Minimum Viable Mailbox

A conformant standalone mailbox implementation must:

- [ ] Implement `MailboxStore` with append-only topic logs and content-addressed message storage
- [ ] Implement `MailboxIngress` accepting `/fwd` exchange envelopes
- [ ] Implement `MailboxEgress` with authenticated polling and message streaming
- [ ] Implement `MailboxProvisioner` processing `/end/role/add` and `/end/role/cut` replies
- [ ] Implement `KeyStateResolver` with at least one resolution strategy
- [ ] Implement poller authentication via challenge-response
- [ ] Have its own non-transferable AID
- [ ] Serve over TLS
- [ ] Support multi-tenancy (multiple recipient AIDs per instance)

### 14.2 Recommended Extensions

A production mailbox should additionally:

- [ ] Implement sender authentication on ingress
- [ ] Implement retention policies (time-based and/or size-based)
- [ ] Publish mailbox-role OOBIs for discovery
- [ ] Implement rate limiting and per-AID storage quotas
- [ ] Support proxy authorization (KERIA polling on behalf of Signify clients)
- [ ] Provide operational metrics (messages stored, storage used, active tenants)
- [ ] Implement health check and readiness endpoints

---

## Appendix A: Interface Summary

```
MailboxStore
    store(topic, payload) → StoreResult
    retrieve(topic, fromOrdinal) → Iterator
    retrieveMulti(recipient, topicCursors) → Iterator
    provision(recipient) → void
    deprovision(recipient) → void
    isProvisioned(recipient) → bool
    trim(topic, beforeOrdinal) → uint64
    trimByAge(recipient, maxAge) → uint64

MailboxIngress
    submit(sender, recipient, topic, payload, authorization) → SubmitResult

MailboxEgress
    poll(poller, recipient, credentials, topicCursors) → Stream<EgressEvent>

MailboxProvisioner
    processAuthorization(reply) → ProvisionResult
    isAuthorized(recipient) → bool
    listAuthorized() → List<AID>

KeyStateResolver
    resolve(aid) → KeyState?
    refresh(aid) → KeyState?
```

## Appendix B: Topic Reference

| Topic | Typical Producers | Content Description |
|-------|-------------------|---------------------|
| `/receipt` | Witnesses | Signed endorsements of key events |
| `/reply` | Any controller | Direct peer-to-peer exchange responses |
| `/replay` | Any controller | Historical KEL segments |
| `/delegate` | Delegators, delegates | Delegation requests and approval events |
| `/multisig` | Multisig participants | Signature contributions, join/rotate coordination |
| `/credential` | Issuers, holders, verifiers | IPEX grant/admit/offer/agree/spurn messages |
| `/challenge` | Any controller | Authentication challenge words and responses |
| `/oobi` | Any controller | OOBI resolution requests |

## Appendix C: Comparison with Related Systems

| System | Similarity | Key Difference |
|--------|-----------|----------------|
| Email (SMTP/IMAP) | Store-and-forward, multi-tenant | Email parses content; mailbox doesn't. Email has global routing (MX); mailbox uses KERI OOBIs. |
| Apache Kafka | Append-only log, consumer cursors, topic partitioning | Kafka has consumer groups with server-side offset tracking; mailbox cursors are client-side only. |
| DIDComm Mediators | Store-and-forward for offline agents, similar relay role | DIDComm mediators may perform encryption/decryption; KERI mailbox is payload-opaque. |
| XMPP Offline Storage | Queues messages for offline users | XMPP dequeues on delivery; mailbox uses log semantics. |

---

*End of specification.*
