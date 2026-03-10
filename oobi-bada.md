# BADA: Best Available Data Acceptance and Endpoint Authorization

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Specifies the BADA acceptance policy for reply messages and OKEA endpoint authorization in KERI
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation

---

BADA (Best Available Data Acceptance) is the acceptance policy applied to all
KERI reply messages (`rpy` type). OKEA (OOBI KERI Endpoint Authorization) is
the specific application of BADA for managing endpoint role assignments and
location schemes. This specification is **not watcher-specific** — BADA
governs all reply message acceptance across the KERI protocol.

---

## 1. Purpose and Scope

KERI's Key Event Log (KEL) uses a totally ordered, append-only structure.
However, much auxiliary data — endpoint locations, role assignments, key
state notices — is communicated via reply messages (`rpy`) that exist
**outside** the KEL. These reply messages need an acceptance policy that
determines when new data supersedes old data.

BADA provides this policy: a pairwise, latest-seen-signed comparison that
ensures monotonic progress of auxiliary state without requiring global
ordering or consensus.

### 1.1 What This Spec Covers

- The BADA acceptance algorithm for all `rpy` messages
- Reply message routing and dispatch
- Endpoint role authorization via `/end/role/add` and `/end/role/cut`
- Location scheme management via `/loc/scheme`
- The RUN (Read, Update, Nullify) operational model
- Escrow handling for partially verified replies

### 1.2 What This Spec Does Not Cover

- KEL event processing (see KEL specification)
- OOBI discovery and URL formats (see [OOBI Core](oobi-core.md))
- Watcher-specific behavior (see watcher specification)
- Credential and exchange semantics

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **BADA** | Best Available Data Acceptance — acceptance policy for reply messages |
| **OKEA** | OOBI KERI Endpoint Authorization — BADA applied to endpoint management |
| **RUN** | Read, Update, Nullify — KERI's operational model (replaces CRUD) |
| **Reply Message** | A `rpy`-type KERI event carrying auxiliary data |
| **Route** | The `r` field in a reply message, identifying the data type |
| **CID** | Controller Identifier — the AID authorizing an endpoint role |
| **EID** | Endpoint Identifier — the AID of the service provider |
| **Establishment Event** | A KEL event that changes key state (icp, rot, dip, drt) |
| **Transferable** | An AID with rotatable keys (has a KEL with establishment events) |
| **Non-transferable** | An AID with fixed keys (single-use, no rotation) |

---

## 3. BADA Policy

### 3.1 Core Principle: Latest-Seen-Signed

BADA determines whether a new reply message should replace an existing
(old) accepted reply from the same source for the same route. The decision
is based on a pairwise comparison: is the new reply **later** than the old?

The definition of "later" depends on whether the signer is transferable
or non-transferable.

### 3.2 Transferable Signer Rules

For a transferable signer (an AID with a KEL), "later" is determined by
comparing the signing establishment events:

**Rule A — Higher sequence number:**
If the sequence number (`sn`) of the establishment event providing the
signing keys for the new reply is **greater than** the `sn` of the
establishment event for the old reply, the new reply is later.

**Rule B — Same sequence number, later datetime:**
If the `sn` values are equal, the new reply is later only if its
datetime stamp (`dt`) is **strictly greater than** the old reply's datetime.

**Combined:**
```
new_is_later = (new_sn > old_sn) OR (new_sn == old_sn AND new_dt > old_dt)
```

**Signature verification for transferable signers:**

Transferable signatures are provided as indexed signature groups (TSGs),
each containing:
- `prefixer` — the signer's AID prefix
- `seqner` — the sequence number of the signer's establishment event
- `diger` — the digest (SAID) of the signer's establishment event
- `sigers` — list of indexed signatures from the signer's key set

Verification requires:
1. The signer's establishment event at the given `sn` must exist in the
   local database
2. The SAID of that event must match the provided `diger`
3. The signatures must verify against the keys from that establishment event
4. The number of valid signatures must meet the signing threshold

### 3.3 Non-Transferable Signer Rules

For a non-transferable signer (an AID with fixed keys, no key rotation),
"later" is determined solely by datetime:

```
new_is_later = (new_dt > old_dt)
```

**Signature verification for non-transferable signers:**

Non-transferable signatures are provided as unindexed signature couples
(cigars), each containing:
- `verfer` — the signer's public key
- `raw` — the signature bytes

Verification requires:
1. The `verfer` must NOT be transferable
2. The `verfer.qb64` must equal the authorizing AID
3. The signature must verify against the signer's public key and the
   serialized reply message

### 3.4 Escrow Conditions

Replies that cannot be immediately verified are escrowed rather than
discarded. Escrow occurs in two cases:

**Missing establishment event:**
For transferable signers, if the signing establishment event at the given
`sn` is not yet in the local database, the reply is escrowed in the `rpes`
(reply escrows) table. A cue is emitted to request the missing key state.

**Partial signatures:**
For transferable signers, if the verified signatures do not meet the
signing threshold, the reply is escrowed. Additional signatures may arrive
later and be combined with the escrowed ones.

**Escrow processing:**

Escrowed replies are periodically re-processed by `processEscrowReply`:
1. For each escrowed reply (keyed by route, valued by SAID):
   - Check if the escrow has timed out (default: 3600 seconds)
   - If timed out, remove and discard
   - Otherwise, re-attempt processing via `processReply`
   - If verification succeeds, remove from escrow
   - If still unverified, leave in escrow

### 3.5 Lax and Local Modes

The Revery operates with two mode flags:

- **lax** (`True` by default): When lax, the Revery accepts replies from
  any source. When strict (`lax=False`), the Revery applies ownership checks.
- **local** (`False` by default): When local, the Revery accepts its own
  signatures on replies. When non-local, own signatures are skipped to
  prevent self-endorsement.

These modes prevent a controller from accepting its own reply messages
when processing external data.

---

## 4. Reply Message Routing

### 4.1 Route Registration

Reply messages are dispatched by the `Router` class. Handlers register
route templates with the router:

```python
router.addRoute("/end/role/{action}", kevery, suffix="EndRole")
router.addRoute("/loc/scheme", kevery, suffix="LocScheme")
router.addRoute("/ksn/{aid}", kevery, suffix="KeyStateNotice")
router.addRoute("/watcher/{aid}/{action}", kevery, suffix="AddWatched")
router.addRoute("/introduce", oobiery)
```

Route templates support URI parameter extraction using `{name}` syntax.
The router compiles templates to regular expressions for matching.

### 4.2 Dispatch

When the Revery receives a reply message, it:
1. Verifies the SAID of the reply via `serder.verify()`
2. Constructs a `Diger` from the SAID
3. Calls `router.dispatch()` with the serder, saider, cigars, and tsgs
4. The router matches the `r` field against registered route regexes
5. The matching handler's `processReply{suffix}()` method is invoked

If no route matches, a `ValidationError` is raised.

---

## 5. Endpoint Authorization (OKEA)

### 5.1 `/end/role/add` — Authorize Endpoint

Authorizes an endpoint provider (EID) to act in a specific role for a
controller (CID). This is an out-of-band authorization — it requires only
signature verification, not KEL anchoring.

**Reply message format:**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "d": "<SAID>",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r": "/end/role/add",
  "a": {
    "cid": "<controller AID>",
    "role": "witness",
    "eid": "<endpoint provider AID>"
  }
}
```

**Required attributes (`a` field):**
- `cid` — the controller AID authorizing the endpoint (must be valid CESR prefix)
- `role` — one of the defined roles (witness, watcher, mailbox, agent, etc.)
- `eid` — the endpoint provider AID being authorized (must be valid CESR prefix)

**Processing logic:**

1. Extract `cid`, `role`, `eid` from the reply attributes
2. Validate all are present and properly formatted
3. Validate `role` is a recognized role from `kering.Roles`
4. Set `aid = cid` (the authorizing attribution ID)
5. Look up any existing authorization via `db.eans.get(keys=(cid, role, eid))`
6. Apply BADA acceptance via `acceptReply()`
7. If accepted, call `updateEnd()`:
   - Store the reply SAID in `db.eans` keyed by `(cid, role, eid)`
   - Create or update an `EndpointRecord` in `db.ends` with `allowed=True`

### 5.2 `/end/role/cut` — Deauthorize Endpoint

Deauthorizes a previously authorized endpoint provider. Uses the same
message format as `/end/role/add` but with route `/end/role/cut`.

**Reply message format:**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "d": "<SAID>",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r": "/end/role/cut",
  "a": {
    "cid": "<controller AID>",
    "role": "witness",
    "eid": "<endpoint provider AID>"
  }
}
```

Processing is identical to `/end/role/add` except `allowed` is set to `False`
in the `EndpointRecord`.

### 5.3 Database Schema

**`EndpointRecord`** (stored in `db.ends`, keyed by `(cid, role, eid)`):

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | bool/None | `True` = authorized (add), `False` = deauthorized (cut), `None` = no reply yet |
| `enabled` | bool/None | `True` = enabled via expose, `False` = disabled, `None` = no expose yet |
| `name` | str | Optional user-friendly name for the endpoint |

**`db.eans`** (endpoint authorization SAIDs):
- Key: `(cid, role, eid)`
- Value: `Diger` (SAID of the authorizing reply message)

### 5.4 Verification

Endpoint authorization is **out-of-band** to the KEL. It requires:
- A valid signature from the CID (the controller authorizing the endpoint)
- BADA acceptance (the reply must be later than any existing reply for the same `(cid, role, eid)` tuple)

It does NOT require:
- Anchoring in the KEL
- Witness receipts
- Any consensus mechanism

---

## 6. Location Scheme Management (`/loc/scheme`)

Location schemes map an endpoint provider (EID) to a URL at a given protocol
scheme. This tells the system "endpoint X is reachable at this URL."

### 6.1 Reply Message Format

**Enact (set URL):**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "d": "<SAID>",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r": "/loc/scheme",
  "a": {
    "eid": "<endpoint provider AID>",
    "scheme": "http",
    "url": "http://localhost:8080/watcher/wilma"
  }
}
```

**Nullify (clear URL):**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "d": "<SAID>",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r": "/loc/scheme",
  "a": {
    "eid": "<endpoint provider AID>",
    "scheme": "http",
    "url": ""
  }
}
```

### 6.2 Required Attributes

- `eid` — the endpoint provider AID (must be valid CESR prefix)
- `scheme` — protocol scheme: `tcp`, `http`, or `https`
- `url` — the full URL (empty string to nullify)

If the URL contains a scheme component, it must match the `scheme` field.
An empty URL scheme is allowed (the `scheme` field is used instead).

### 6.3 Processing Logic

1. Extract `eid`, `scheme`, `url` from the reply attributes
2. Validate all are present and properly formatted
3. Validate `scheme` is a recognized scheme from `kering.Schemes`
4. If URL has a scheme component, verify it matches the `scheme` field
5. Set `aid = eid` (the endpoint provider authorizes its own location)
6. Look up existing authorization via `db.lans.get(keys=(eid, scheme))`
7. Apply BADA acceptance via `acceptReply()`
8. If accepted, call `updateLoc()`:
   - Store the reply SAID in `db.lans` keyed by `(eid, scheme)`
   - Create or update a `LocationRecord` in `db.locs` with the URL

### 6.4 Database Schema

**`LocationRecord`** (stored in `db.locs`, keyed by `(eid, scheme)`):

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Full URL including host:port/path?query |

**`db.lans`** (location authorization SAIDs):
- Key: `(eid, scheme)`
- Value: `Diger` (SAID of the authorizing reply message)

---

## 7. RUN (Read, Update, Nullify)

KERI uses RUN instead of CRUD for managing auxiliary state. The rationale:

| CRUD | RUN | KERI Semantics |
|------|-----|----------------|
| Create | (implicit) | First write creates the record |
| Read | **Read** | Query current state |
| Update | **Update** | Submit a later-dated reply to replace existing state |
| Delete | **Nullify** | Submit a reply that clears the value (empty URL, `cut` action) |

**Why not Delete?**
In KERI, records are never truly deleted — they are nullified. The reply
message that nullifies a record is itself stored and subject to BADA. This
maintains an audit trail and prevents replay of old, pre-deletion state.

**Endpoint authorization uses Add/Cut:**
- `/end/role/add` — sets `allowed=True` (Update)
- `/end/role/cut` — sets `allowed=False` (Nullify)

**Location scheme uses Enact/Nullify:**
- `/loc/scheme` with non-empty URL — sets the location (Update)
- `/loc/scheme` with empty URL — clears the location (Nullify)

---

## 8. Role Vocabulary

The following roles are defined in `kering.Roles`:

| Role | Standardized | Description |
|------|-------------|-------------|
| `controller` | Yes | The AID itself acting as its own endpoint |
| `witness` | Yes | Event receipt and persistence service |
| `watcher` | Yes | Duplicity detection and key state monitoring |
| `registrar` | Yes | Credential registry service |
| `gateway` | Yes | Network gateway service |
| `judge` | Yes | Adjudication service |
| `juror` | Yes | Jury participation service |
| `peer` | Yes | Generic peer endpoint |
| `mailbox` | **Extension** | Asynchronous message relay (not yet in KERI spec) |
| `agent` | **Extension** | Cloud agent proxy service (not yet in KERI spec) |
| `indexer` | **Extension** | Indexing service (not yet in KERI spec) |

The `mailbox` and `agent` roles are widely used in the keripy ecosystem
(KERIA, signify-ts) but have not yet been standardized in the KERI
specification. Implementations should treat them as implementation-defined
extensions.

---

## 9. Reply SAD Storage

All accepted reply messages are stored in a set of related database tables:

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `sdts` | SAID | `Dater` | Datetime of the accepted reply |
| `rpys` | SAID | `Serder` | The full serialized reply message |
| `scgs` | SAID | `(Verfer, Cigar)` | Non-transferable signature couples |
| `ssgs` | SAID.pre.sn.dig | `[Siger]` | Transferable indexed signature groups |
| `rpes` | route | `[Diger]` | Escrowed reply SAIDs by route |

When a new reply supersedes an old one, the old reply's artifacts are
removed from all tables via `removeReply()`.

---

## 10. Security Considerations

### 10.1 Replay Attacks

BADA prevents replay by requiring strict monotonic progress — a replayed
reply with an old datetime or old establishment event sequence number will
be rejected.

### 10.2 Forged Endpoint Authorization

An attacker cannot forge an endpoint authorization without the controller's
private keys. The reply message must be signed by the CID's current keys
(for `/end/role`) or the EID's current keys (for `/loc/scheme`).

### 10.3 Stale Key State

If a signer has rotated keys, old signatures from pre-rotation keys are
still valid for their establishment event `sn`. However, a new reply
signed with post-rotation keys will have a higher `sn` and will supersede
any reply signed with older keys.

### 10.4 Escrow Abuse

An attacker could flood the system with unverifiable replies to consume
escrow storage. Mitigation: escrows timeout after 3600 seconds (configurable
via `TimeoutRPE`).

### 10.5 Self-Endorsement Prevention

The `lax` and `local` mode flags prevent a node from accepting its own
reply messages when processing external data. In non-local mode (`local=False`),
a node's own signatures on reply messages are skipped, preventing
self-endorsement of externally received data.

---

## 11. Implementation Notes

### 11.1 Route Handler Registration

The Kevery registers its reply routes during initialization:

```python
def registerReplyRoutes(self, router):
    router.addRoute("/end/role/{action}", self, suffix="EndRole")
    router.addRoute("/loc/scheme", self, suffix="LocScheme")
    router.addRoute("/ksn/{aid}", self, suffix="KeyStateNotice")
    router.addRoute("/watcher/{aid}/{action}", self, suffix="AddWatched")
```

The suffix maps to handler methods:
- `/end/role/{action}` maps to `processReplyEndRole()`
- `/loc/scheme` maps to `processReplyLocScheme()`
- `/ksn/{aid}` maps to `processReplyKeyStateNotice()`

### 11.2 Endpoint Discovery Flow

The complete flow from OOBI to usable endpoint:

```
1. Receive OOBI URL for AID
2. HTTP GET → receive CESR stream
3. Parse stream through Kevery (validates KEL events)
4. Parse stream through Revery (validates reply messages)
5. /end/role/add reply → BADA → store (cid, role, eid) in db.ends
6. /loc/scheme reply → BADA → store (eid, scheme) → url in db.locs
7. To reach AID: lookup db.ends for (cid, role, *) → get eid
                  lookup db.locs for (eid, scheme) → get url
```

### 11.3 Database Cloning

When cloning a database (e.g., for backup or migration), endpoint and
location records are handled specially:
- For each `(cid, role, eid)` in `db.ends`, check if matching location
  records exist in `db.locs` for the eid
- Only clone endpoint records that have at least one matching location
- Clone matching location records for all supported schemes (https, http, tcp)

This ensures the cloned database does not contain orphaned endpoint
records without corresponding location information.
