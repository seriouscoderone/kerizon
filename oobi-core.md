# OOBI Discovery Protocol

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Specifies the Out-of-Band Introduction (OOBI) discovery mechanism for KERI identifiers
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation

---

OOBI is the discovery and bootstrap mechanism for KERI. It provides a way for
identifiers to discover each other's service endpoints without requiring any
centralized directory. OOBI is **standalone** — it does not require watchers
or any other infrastructure beyond the endpoints being discovered.

---

## 1. Purpose and Scope

KERI identifiers are self-certifying — they can be created and verified
independently. However, to communicate, controllers must discover where to
reach each other. OOBI solves this discovery problem.

An OOBI is an untrusted `(URL, AID)` tuple that provides a discovery hint.
The tuple tells a resolver "you might find information about this AID at this
URL." The resolver then fetches the URL, retrieves a KERI event stream or
reply message, and cryptographically verifies everything it receives. Trust
comes from KERI verification, never from the OOBI itself.

### 1.1 What OOBI Does Not Cover

- OOBI does not define how events are validated (see KEL specification)
- OOBI does not define watcher or witness behavior (see respective specs)
- OOBI does not specify transport security (TLS, etc.)
- OOBI does not define credential exchange (see ACDC/IPEX specs)

### 1.2 Design Principle

OOBIs follow a "trust but verify" model:
1. Accept any discovery hint from any source
2. Fetch the hinted endpoint
3. Cryptographically verify everything received
4. Cache verified associations

The hint itself carries zero trust. A malicious OOBI can point to a
non-existent endpoint, a wrong AID, or a compromised host — the verifier
will detect all of these through cryptographic validation.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **OOBI** | Out-of-Band Introduction — an untrusted `(URL, AID)` tuple |
| **DOOBI** | Data OOBI — an OOBI for schema or data resources identified by SAID |
| **WOOBI** | Well-Known OOBI — uses `/.well-known/` URL convention for discovery |
| **MOOBI** | Multi-OOBI — batch resolution of multiple OOBIs for one AID |
| **SOOBI** | Self/Blind OOBI — self-referential introduction with no pre-specified AID |
| **SPED** | Speedy Percolated Endpoint Discovery — JIT/NTK (Just-In-Time / Need-To-Know) discovery |
| **IURL** | Introduction URL — the URL component of an OOBI |
| **CID** | Controller Identifier — the AID being introduced |
| **EID** | Endpoint Identifier — the AID of the service provider (witness, watcher, etc.) |
| **Role** | The function an EID performs for a CID (witness, watcher, mailbox, agent) |

---

## 3. OOBI Trust Model

### 3.1 Untrusted Hint

An OOBI is explicitly untrusted. It is a bootstrap mechanism — a way to get
the process of cryptographic verification started. The OOBI itself provides:
- A URL to query
- An optional AID to associate with the response
- An optional role hint

None of these are trusted until verified.

### 3.2 Verification via KERI

After fetching the OOBI URL, the resolver receives one of:
- A CESR event stream (`application/json+cesr`) containing the AID's KEL and/or reply messages
- A JSON reply message (`application/json`) containing endpoint information
- A schema document (`application/schema+json`) for data OOBIs

For CESR streams, the resolver processes all events through its local Kevery
(key event verifier) and Revery (reply event verifier). Only cryptographically
valid events update the resolver's local state.

### 3.3 Caching

Once verified, the resolver caches the association between the AID and the
endpoint. This cache is maintained in the local database via endpoint
authorization records (`/end/role/add`) and location records (`/loc/scheme`).
See the [OOBI BADA specification](oobi-bada.md) for the acceptance policy
that governs cache updates.

---

## 4. URL Formats

### 4.1 Role-Based OOBI

The most common form. Encodes the CID, role, and optionally the EID in the path.

**Format:** `{scheme}://{host}:{port}/oobi/{cid}/{role}/{eid}`

**Path regex:** `\A/oobi/(?P<cid>[^/]+)/(?P<role>[^/]+)(?:/(?P<eid>[^/]+))?\Z`

**Components:**
- `cid` — the AID being discovered (CESR-qualified, e.g., `D` prefix for Ed25519)
- `role` — the role of the endpoint provider (witness, watcher, mailbox, agent, controller)
- `eid` — (optional) the AID of the specific endpoint provider

**Examples:**
```
http://witness1.example.com:5632/oobi/ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On/witness/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw
http://witness1.example.com:5632/oobi/ENcOes8_t2C7tck4X4j61fSm0sWkLbZrEZffq7mSn8On/witness
```

When `eid` is omitted, the server responds with information for all known
endpoints in that role for the given CID.

**Resolution behavior:**

The server receiving a role-based OOBI request:
1. Looks up the `cid` in its local kevers (key state database)
2. Verifies it has fully witnessed the AID's inception/latest event
3. If the AID is delegated, verifies the delegator is also known
4. Responds with reply messages (`rpy`) containing endpoint authorizations and location schemes, plus the AID's KEL as a CESR stream

The response uses content type `application/json+cesr` and includes a
`KERI-AID` header identifying the resolved AID.

### 4.2 Data OOBI (DOOBI)

For discovering data resources identified by their SAID (Self-Addressing
IDentifier), such as JSON schemas for ACDC credentials.

**Format:** `{scheme}://{host}:{port}/oobi/{said}`

**Path regex:** `\A/oobi/(?P<said>[^/]+)\Z`

**Components:**
- `said` — the SAID of the data resource

**Example:**
```
http://schema.example.com:7723/oobi/EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM
```

**Resolution behavior:**

The server responds with the data resource (typically a JSON schema). The
resolver verifies the SAID of the response matches the requested SAID. The
response uses content type `application/schema+json`.

### 4.3 Well-Known OOBI (WOOBI)

Uses the IETF `.well-known` URI convention (RFC 8615) for discovery.

**Format:** `{scheme}://{host}:{port}/.well-known/keri/oobi/{cid}`

**Path regex:** `\A/.well-known/keri/oobi/(?P<cid>[^/]+)\Z`

WOOBIs serve a dual purpose:
1. **Discovery:** Same as a standard role-based OOBI
2. **Multi-Factor Authentication (MFA):** A WOOBI can provide web-based
   confirmation that an AID controls a domain. If a domain's
   `/.well-known/keri/oobi/{cid}` endpoint responds successfully, it
   provides a second factor associating the AID with that domain.

**MFA flow:**

The `Authenticator` class processes WOOBIs for MFA:
1. Resolve the WOOBI to confirm the AID exists in local kevers
2. HTTP GET the WOOBI URL
3. If the response is successful (2xx/3xx), record the association as a
   `WellKnownAuthN` record linking the CID to the domain URL

This provides domain-level authentication — the AID controller demonstrates
control of the web domain by hosting a valid WOOBI endpoint.

### 4.4 Multi-OOBI (MOOBI)

A mechanism for batch resolution. When a role-based OOBI response contains a
reply message with route `/oobi/witness` or `/oobi/controller`, the response
includes a list of individual OOBI URLs that should all be resolved.

**Reply message format:**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "r": "/oobi/witness",
  "a": {
    "aid": "<CID>",
    "urls": [
      "http://witness1.example.com:5632/oobi/<CID>/witness/<WIT1>",
      "http://witness2.example.com:5633/oobi/<CID>/witness/<WIT2>"
    ]
  }
}
```

**Resolution behavior:**

The resolver processes all URLs in the list as individual OOBIs. The
original MOOBI is considered resolved only when all constituent OOBIs
have been resolved. If any constituent OOBI fails, the entire MOOBI fails.

The MOOBI tracks constituent resolution state via the `moobi` sub-database,
monitoring each URL's resolution status in `roobi`.

### 4.5 Self/Blind OOBI (SOOBI)

A self-referential introduction where the path is simply `/oobi` with no
AID in the URL. Used for blind introductions where the resolver does not
know in advance which AID will be returned.

**Format:** `{scheme}://{host}:{port}/oobi`

The resolver sends an HTTP GET to the URL. The response contains an event
stream or reply message from which the resolver extracts the AID. If the
server has a `default` AID configured, it responds with that AID's
information. Otherwise, it returns 404.

**Query parameter support:**

All OOBI URL formats support a `name` query parameter that provides an
alias hint:
```
http://witness.example.com:5632/oobi?name=Alice
http://witness.example.com:5632/oobi/ENcOes8_t2/witness?name=Bob
```

The `name` parameter populates the `oobialias` field in the OOBI record,
providing a human-readable label for contact organization.

---

## 5. Resolution Protocol

### 5.1 Resolution Flow

OOBI resolution is managed by the `Oobiery` class, which operates as an
asynchronous doer processing OOBIs from the database.

**Database tables involved:**

| Table | Purpose |
|-------|---------|
| `oobis` | Pending OOBIs to resolve |
| `coobi` | OOBIs with active HTTP clients (in-flight requests) |
| `roobi` | Resolved OOBIs with final state (resolved/failed) |
| `eoobi` | OOBIs pending retry after failure |
| `moobi` | Multi-OOBI tracking records |
| `woobi` | Well-known OOBIs pending MFA processing |

**Flow:**

```
    OOBI received (URL)
         │
         ▼
    ┌─────────┐
    │  oobis  │  Pin new OOBI record
    └────┬────┘
         │  processOobis()
         ▼
    Parse URL format
    (OOBI_RE / DOOBI_RE / WOOBI_RE / bare /oobi)
         │
         ▼
    Extract cid, eid, role, said from path
         │
         ▼
    ┌─────────┐
    │  coobi  │  Move to in-flight, create HTTP client
    └────┬────┘
         │  processClients()
         ▼
    HTTP GET response received
         │
         ├── 404 → move to eoobi (retry escrow)
         ├── non-200 → mark failed in roobi
         │
         ├── application/json+cesr
         │   └── Parse CESR stream through Kevery+Revery
         │       └── mark resolved in roobi
         │
         ├── application/schema+json
         │   └── Validate SAID matches
         │       └── Store in schema DB, mark resolved
         │
         └── application/json
             ├── Try as schema → validate SAID
             └── Try as rpy → check route
                 ├── /oobi/witness → processMultiOobiRpy (MOOBI)
                 └── /oobi/controller → processMultiOobiRpy (MOOBI)
```

### 5.2 Response Handling

**CESR Stream Response (`application/json+cesr`):**

The primary response format. Contains a complete CESR event stream that is
parsed by a local `Parser` instance configured with:
- A `Kevery` (key event verifier) in `lax=True, local=False` mode — promiscuous, non-local
- A `Revery` (reply event verifier) for processing embedded `rpy` messages
- Reply routes registered for `/end/role/{action}`, `/loc/scheme`, and `/ksn/{aid}`

The parser processes all events in the stream, updating the local key state
database. The `KERI-AID` response header identifies which AID was resolved.

**Schema Response (`application/schema+json`):**

For DOOBI requests. The response body is validated as a `Schemer` and its
SAID is compared to the requested SAID. If they match, the schema is stored
in the schema database.

**JSON Reply Response (`application/json`):**

An unsigned `rpy` message. Currently supported routes:
- `/oobi/witness` — triggers MOOBI processing with witness URLs
- `/oobi/controller` — triggers MOOBI processing with controller URLs

### 5.3 Verification

All verification is performed by the standard KERI event processing pipeline:
- **KEL events** (icp, rot, ixn, etc.) are verified by the Kevery
- **Reply messages** (rpy) are verified by the Revery using the BADA algorithm (see [OOBI BADA specification](oobi-bada.md))
- **Schemas** are verified by SAID comparison

No OOBI-specific verification logic exists — OOBI delegates all trust
decisions to the underlying KERI protocol.

### 5.4 Retry and Caching

**Retry policy:**

Failed OOBIs (404 responses) are moved to the `eoobi` escrow table. The
`processRetries` method checks escrowed OOBIs and re-queues them for
resolution after a configurable delay (default: 30 seconds).

```
RetryDelay = 30  # seconds
```

**Caching:**

Resolved OOBIs are stored in the `roobi` table with their final state.
When a previously resolved OOBI is submitted again, it is skipped if already
in `roobi` with state `resolved` and also present in `eoobi`.

If an OOBI alias was provided (via `oobialias` in the OOBI record or the
`name` query parameter), the resolver updates the contact organizer with the
alias and OOBI URL for the resolved CID.

---

## 6. OOBI Forwarding

OOBI forwarding enables one controller to introduce another via a reply
message with route `/introduce`.

**Reply message format:**
```json
{
  "v": "KERI10JSON00011c_",
  "t": "rpy",
  "d": "<SAID>",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r": "/introduce",
  "a": {
    "cid": "<AID of the introduced party>",
    "oobi": "http://witness.example.com:5632/oobi/<AID>/witness"
  }
}
```

The `/introduce` route is registered by the `Oobiery` and processed via
`processReply`. The handler:
1. Validates the `cid` as a valid CESR prefix
2. Validates the OOBI URL scheme (must be `http` or `https`)
3. Applies BADA acceptance (always accepts introductions since there is no
   prior reply to compare against)
4. Queues the OOBI URL for standard resolution

This enables transitive discovery — Controller A introduces Controller C
to Controller B by forwarding C's OOBI.

---

## 7. Peer-to-Peer OOBI Exchange

Controllers can request OOBI resolution from peers using the `exn`
(exchange) message protocol.

**Exchange message resource:** `/oobis`

The `OobiRequestHandler` processes incoming `exn` messages containing an
OOBI URL. Upon receipt:
1. Creates an `OobiRecord` with the current timestamp
2. Queues the OOBI for resolution
3. Generates a notification for the controller's UI

**Exchange message payload:**
```json
{
  "dest": "<destination AID>",
  "oobi": "<OOBI URL>"
}
```

The `oobiRequestExn` function creates the outbound exchange message,
endorsed (signed) by the sender's Hab.

---

## 8. SPED (Speedy Percolated Endpoint Discovery)

SPED provides Just-In-Time / Need-To-Know endpoint discovery. Rather than
pre-resolving all possible endpoints, SPED resolves endpoints on demand
when communication is first needed.

The SPED concept is embedded in the OOBI resolution flow — when a
controller needs to reach another controller and does not have cached
endpoint information, it resolves an OOBI to discover the endpoint. This
lazy resolution avoids the overhead of maintaining a global endpoint
directory.

---

## 9. OOBI with MFA

WOOBIs can provide multi-factor authentication by associating an AID with
a web domain. The `Authenticator` class implements this:

1. WOOBIs are stored in the `woobi` database table
2. The authenticator processes each WOOBI by:
   a. Validating the URL matches the WOOBI regex
   b. Checking the CID exists in local kevers
   c. Sending an HTTP GET to the WOOBI URL
3. If the response succeeds (2xx/3xx):
   - A `WellKnownAuthN` record is created with the URL and timestamp
   - The record is stored in the `wkas` (well-known auth) database keyed by CID
4. Results are stored in `rmfa` (resolved MFA) table

This provides a second factor: the AID controller demonstrates domain control
by hosting a valid endpoint at `/.well-known/keri/oobi/{cid}` on their domain.

---

## 10. Role Types and Endpoints

The role in a role-based OOBI identifies the function of the endpoint
provider. Defined roles (from `kering.py`):

| Role | Description | Typical EID |
|------|-------------|-------------|
| `controller` | The AID itself serves as its own endpoint | Transferable |
| `witness` | Receipts and event persistence | Non-transferable |
| `watcher` | Duplicity detection and key state monitoring | Non-transferable |
| `mailbox` | Asynchronous message relay (implementation extension) | Non-transferable |
| `agent` | Cloud agent proxy (e.g., KERIA) | Transferable |
| `registrar` | Credential registry | Transferable |
| `gateway` | Network gateway | Transferable |
| `judge` | Adjudicator | Transferable |
| `juror` | Jury member | Transferable |
| `peer` | Peer endpoint | Transferable |
| `indexer` | Indexing service | Transferable |

The `witness`, `watcher`, `mailbox`, and `agent` roles are the most commonly
used for OOBI resolution. The `mailbox` role is an implementation extension
not yet standardized in the KERI specification. See the
[Mailbox Service Specification](mailbox-service-spec.md) for details.

---

## 11. Security Considerations

### 11.1 OOBI Poisoning

An attacker could distribute malicious OOBIs pointing to compromised endpoints.
Mitigation: All responses are cryptographically verified. A compromised endpoint
cannot forge valid KERI events without the controller's private keys.

### 11.2 Denial of Service via OOBI Flooding

An attacker could submit large numbers of OOBIs to exhaust resolver resources.
Mitigation: Implementers should rate-limit OOBI resolution and prioritize
OOBIs from trusted sources.

### 11.3 OOBI Replay

An attacker could replay old OOBIs with stale endpoint information. Mitigation:
The BADA algorithm ensures only the latest endpoint information is accepted.
See [OOBI BADA specification](oobi-bada.md).

### 11.4 Man-in-the-Middle on OOBI Fetch

Without TLS, the HTTP fetch is vulnerable to interception. Mitigation: The
response content is cryptographically signed — MITM can see but cannot modify
the response without detection. Using HTTPS adds transport-level protection.

### 11.5 Privacy Considerations

OOBI resolution reveals that a resolver is interested in a particular AID.
This is inherent to the discovery process. Controllers concerned about privacy
should use OOBIs over Tor or other anonymizing transports.

---

## 12. Implementation Notes

### 12.1 Server Endpoint Registration

The OOBI server endpoint (`OOBIEnd`) is registered at multiple paths to
handle all URL formats:

```python
app.add_route("/oobi", end)           # SOOBI (blind)
app.add_route("/oobi/{aid}", end)     # DOOBI (by SAID)
app.add_route("/oobi/{aid}/{role}", end)       # Role-based without EID
app.add_route("/oobi/{aid}/{role}/{eid}", end) # Role-based with EID
```

### 12.2 Client API

The `OobiResource` provides a REST API for submitting OOBIs:
- **POST /oobi** — Submit an OOBI URL for resolution. Body: `{"url": "<OOBI URL>", "oobialias": "<optional alias>"}`
- **GET /oobi/{alias}** — Retrieve the OOBI URL(s) for a local identifier by alias and role

### 12.3 Response Content Negotiation

The OOBI server uses the `replyToOobi` method from the Hab to generate
responses. It constructs reply messages for the requested role and, when
no role is specified, defaults to the `witness` role and includes a full
KEL replay.

### 12.4 Database Schema

The `OobiRecord` dataclass stores OOBI processing state:

| Field | Type | Description |
|-------|------|-------------|
| `date` | str | ISO 8601 timestamp of record creation |
| `state` | str | Resolution state: `resolved` or `failed` |
| `cid` | str | Controller identifier extracted from URL |
| `eid` | str | Endpoint identifier extracted from URL |
| `role` | str | Role extracted from URL |
| `said` | str | SAID for data OOBIs |
| `oobialias` | str | Human-readable alias for the resolved AID |
| `urls` | list | Constituent URLs for MOOBIs |
