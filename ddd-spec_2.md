# DDD Specification — Key Event Receipt Infrastructure (keripy)

> Produced by the Domain-Driven Design analysis pipeline.
> Classification system: domain-concept-classification-system.md v1.0

---

## Section 1 — Specification Metadata

| Field | Value |
|---|---|
| **Domain Name** | Key Event Receipt Infrastructure (KERI) — Python Reference Implementation |
| **Specification Author(s)** | AI-generated via decree |
| **Date Created** | 2026-03-06T19:13:00Z |
| **Current Pass Number** | 1 |
| **Status** | Draft |
| **Reference Classification System Version** | 1.0 |
| **Linked Codebases / Repos** | keripy (`src/keri/`) |
| **Linked Spec Files / Feature Files** | KERI Specification v1.0 (Trust Over IP / IETF); CESR Specification (Trust Over IP); ACDC Specification (Trust Over IP); `ref/CypherSuites.md`; `ref/Peer2PeerCredentials.md`; `ref/tel.md`; `ref/MultiHab.md`; `ref/MultisigIssuance.md` |

---

## Section 2 — Ubiquitous Language

Terms are drawn from the KERI Specification, the KERI Whitepaper (v2.63), and the keripy source code. Source column values: `spec` = KERI/CESR/ACDC specifications; `code` = keripy source; `both` = present in both.

| Term | Definition | Source | Notes |
|---|---|---|---|
| **AID (Autonomic Identifier)** | A self-certifying identifier cryptographically bound to a signing key pair at inception. It can be transferred to new key pairs via rotation events and requires no external registry for verification. | both | Code: represented as a CESR-qualified base-64 prefix string (`pre`). The `Prefixer` class in `coring.py` encodes and decodes AIDs. |
| **Key Event** | A signed statement that establishes (`icp`, `dip`) or changes (`rot`, `drt`, `ixn`) the key state of an AID. Key events are sequentially numbered and backward-chained via digest. Event types (ilks): `icp`, `rot`, `ixn`, `dip`, `drt`, `rct`. | both | Code: `Ilks` namedtuple in `kering.py`; event bodies are `SerderKERI` instances. |
| **KEL (Key Event Log)** | An append-only, cryptographically verifiable, backward- and forward-chained sequence of all key events for a single AID. Each event is signed and includes a digest of the prior event. | both | Code: stored in `Baser` LMDB database; queried via `dgKey`/`snKey` helpers in `dbing.py`. |
| **KERL (Key Event Receipt Log)** | A KEL augmented with signed receipts from witnesses for each event. The KERL constitutes the secondary root-of-trust in indirect mode. | both | Code: receipts stored separately in `Baser`; the composite of KEL + receipts is accessed together during validation. |
| **Pre-rotation** | A mechanism where the current establishment event commits to a cryptographic digest of the next rotation key pair. Only the holder of the committed-to private key can perform the next valid rotation, making key compromise recovery possible and live-attack resistance strong. | both | Code: `ndigers` (list of `Diger` instances for next key digests) and `ntholder` (`Tholder`) on `Kever`. |
| **Controller** | The entity or set of entities that hold the private signing keys authorizing control over an AID. The controller produces key events and signs them. In multi-sig, multiple parties collectively constitute the controller. | both | Code: represented as `Hab` (single controller) or a group `Hab` (multi-sig) in `habbing.py`. |
| **Witness** | An infrastructure node designated in a controller's KEL that receipts key events, exchanges receipts with other witnesses, and runs KAWA to agree on first-seen event versions. Witnesses form a promulgation network for an AID. | both | Code: `WitnessStart`, `WitnessReceiptor`, `WitnessPublisher` in `agenting.py` and `indirecting.py`. |
| **Watcher** | An infrastructure node operated by a validator that monitors KELs of other controllers, enforces the first-seen policy, and detects duplicity. Watchers are not declared in a KEL so they remain confidential to the validator. | both | Code: `watching.py` in `app/`; watcher pools are not explicitly named in keripy source. |
| **OOBI (Out-of-Band Introduction)** | A URL + AID pair that bootstraps discovery of an AID's KEL or an infrastructure endpoint (witness, watcher, agent) by providing a resolvable location outside the core KERI protocol. | both | Code: `oobiing.py`; `OobiRecord` in `recording.py`; CLI commands under `cli/commands/oobi/`. |
| **CESR (Composable Event Streaming Representation)** | A qualified base-64 encoding system for KERI cryptographic primitives and messages. Type codes are prepended to raw values to form self-describing, composable streams that support both text (base-64) and binary modes. | both | Code: foundational to all of `keri/core/`; `Matter` and its subclasses (`Verfer`, `Diger`, `Siger`, `Seqner`, `Prefixer`, `Salter`, `Tholder`) encode typed primitives. |
| **SAID (Self-Addressing Identifier)** | A content-addressable identifier computed as the cryptographic digest of the data structure it identifies, embedded within that structure at a designated field. SAIDs make data self-referentially verifiable. | both | Code: `Saids` namedtuple in `coring.py`; field label convention `d` or `$id`. SAIDive processing is done in `Serder`. |
| **Seal** | A cryptographic digest commitment included as an anchor in a KEL event that binds external data (such as a credential issuance or registry event) to a specific key state at a specific sequence number. | both | Code: `SealEvent`, `SealLast` dataclasses in `structing.py`; used in `eventing.py` during interaction and rotation event construction. |
| **Duplicity** | The existence of two or more verifiably signed, conflicting key events at the same sequence number for the same AID. Duplicity is provable evidence of either key compromise or malicious controller behavior. | both | Code: `LikelyDuplicitousError` in `kering.py`; duplicity checking in `Kevery` (eventing.py). |
| **KAWA (KERI's Algorithm for Witness Agreement)** | The Byzantine-fault-tolerant consensus algorithm by which a pool of witnesses reaches agreement on the first-seen, authoritative version of each key event. KAWA provides high-availability and fault-tolerance guarantees equivalent to or exceeding distributed ledger approaches for a single AID's KEL. | both | Code: `ample()` / `simple()` functions in `eventing.py` compute TOAD (Threshold of Accountable Duplicity) values used for quorum calculations. |
| **Escrow** | A temporary holding area for key events or receipts that cannot yet be applied because prerequisite data is missing (out-of-order events, insufficient signatures, pending delegation approval, missing witness receipts). Escrowed events are re-evaluated as new data arrives. | code | Spec implies deferred processing but does not name "escrow" as a formal mechanism. Code: `escrowing.py`; multiple escrow buckets in `Kevery`. |
| **Kever (Key Event Verifier)** | The runtime in-memory object that tracks the current fully verified key state of a single AID. Holds: current signing keys (`verfers`), next key digests (`ndigers`), signing threshold (`tholder`), witness list (`wits`), sequence number (`sn`), and first-seen ordinal (`fn`). | code | Absent from spec by this name. The spec refers to "key state" as the abstract concept; `Kever` is keripy's authoritative implementation of that concept. Class: `eventing.Kever`. |
| **Hab / Habery (Habitat / Habitat Registry)** | `Hab` is a keripy-specific abstraction that bundles together a single locally controlled AID with its Kever, database reference, key manager, and event processor into one operable unit. `Habery` is the registry that owns the shared keystore and database across multiple `Hab` instances. | code | Absent from KERI specification by name. "Habitat" is an informal code-layer concept with no spec equivalent. Source: `habbing.py`. |
| **Inception Event (icp)** | The first and only event that establishes an AID, defining its initial key state, witness pool, signing threshold, next-key digest commitments, and configuration traits. The AID's identifier prefix is derived from the inception event's digest or initial public key. | both | Code: `Ilks.icp`; constructed in `eventing.incept()`; validated by `Kever.__init__()`. |
| **Rotation Event (rot)** | An establishment event that transfers control of an AID to a new signing key set whose digests were pre-committed in the prior establishment event. Updates the key state and optionally changes the witness pool. | both | Code: `Ilks.rot`; constructed in `eventing.rotate()`; validated by `Kever.update()`. |
| **ACDC (Authentic Chained Data Container)** | A verifiable credential format whose issuance, revocation, and chaining are anchored to KERI AID key states. ACDCs are self-describing, schema-validated, SAID-identified data containers. | both | Code: `keri/acdc/`, `keri/vc/`, `keri/vdr/`; `SerderACDC` in `serdering.py`. |

**Terms in code absent from KERI specifications:**

| Code Term | Code Location | Notes |
|---|---|---|
| `Kever` | `core/eventing.py:1586` | Spec calls this "key state"; no named class counterpart in spec. |
| `Hab` / `Habery` | `app/habbing.py:2166` / `:111` | Informal "habitat" metaphor; not a spec term. |
| `Escrow` (as named mechanism) | `db/escrowing.py`, `core/eventing.py` | Spec implies deferred processing; escrow is not named in spec prose. |
| `Baser` | `db/basing.py:164` | Internal LMDB database abstraction; spec is storage-agnostic. |
| `TOAD` (Threshold of Accountable Duplicity) | `core/eventing.py` (field `toad`) | Used in spec event fields but the acronym "TOAD" is spec-defined; its use as a field name in `Kever.toader` is code-specific. |

---

## Section 3 — Domain Identity

### 3.1 Domain Purpose Statement

keripy implements the Key Event Receipt Infrastructure (KERI) protocol: the mechanism by which controllers establish, transfer, and revoke control over Autonomic Identifiers (AIDs) through cryptographically verifiable Key Event Logs (KELs) that are end-verifiably anchored in pre-rotated signing key pairs. It provides the complete AID lifecycle — inception, rotation, interaction, and delegation — supported by witness-based promulgation in indirect mode and direct peer exchange in direct mode. keripy is the Python reference implementation of the KERI protocol and the authoritative in-language expression of the KERI specification's invariants.

### 3.2 Domain Responsibilities

**IS responsible for:**

1. Establishing AIDs via inception events (`icp`, `dip`) with cryptographic key-pair binding and pre-rotation commitment.
2. Rotating AID key state via rotation events (`rot`, `drt`) that satisfy the pre-rotation commitment made in the prior establishment event.
3. Anchoring external data to AID key state via seals in interaction events (`ixn`) and establishment events.
4. Validating Key Event Logs: structure verification, signature verification, chaining digest verification, and witness receipt quorum verification.
5. Managing hierarchical AID delegation: producing and validating delegated inception (`dip`) and delegated rotation (`drt`) events with delegator approval anchors.
6. Operating witness infrastructure: receipting key events, exchanging receipts with peer witnesses, applying KAWA quorum logic.
7. Operating watcher infrastructure: first-seen enforcement and duplicity detection for watched AIDs.
8. Encoding and decoding all KERI and ACDC protocol messages using CESR-qualified primitives.
9. Issuing, revoking, and verifying ACDC verifiable credentials anchored to AID key state via the Verifiable Data Registry (VDR).
10. Resolving OOBIs to bootstrap AID and infrastructure discovery outside the core protocol stream.

**IS NOT responsible for:**

1. Network transport — HTTP, TCP, and WebSocket are external adapters; the domain owns only the message content and its verification.
2. Application-level identity semantics (e.g., login sessions, user accounts, OAuth flows) — these exist outside the AID key-state domain.
3. Consensus or ordering guarantees beyond KAWA among designated witnesses for a single AID's KEL — no global ordering is required or provided.
4. Hardware security module (HSM) or hardware wallet integration — these are external adapters to the key management port.
5. Business-layer credential semantics — what an ACDC claim means in a given legal or business context is not a domain concern.
6. Blockchain or distributed ledger operations — KERI does not depend on a ledger and keripy does not implement one.

### 3.3 Bounded Context Boundaries

Seven bounded contexts are identified within keripy. Each owns a named core responsibility. Shared kernel dependencies are named explicitly.

---

**BC-1: Event Processing**

- **Core responsibility:** Validate incoming key event messages against KEL invariants and apply them to produce authoritative key state (`Kever`). Enforce all protocol rules: signature thresholds, chaining digests, pre-rotation satisfaction, witness quorum, delegation approval.
- **Primary files:** `core/eventing.py` (`Kever`, `Kevery`), `core/parsing.py`, `core/routing.py`
- **Shared kernel dependency:** CESR Encoding (BC-3) for primitive types; Persistence (BC-4) for KEL storage and key state cache.
- **Shared kernel export:** `Kever` is a shared read-only value object consumed by all bounded contexts. BC-1 retains exclusive mutation authority: `Kever.__init__()` and `Kever.update()` are the only valid entry points for key state change. All other BCs treat Kever as a read-only domain value object.

---

**BC-2: Key Management**

- **Core responsibility:** Generate, store (encrypted), and rotate cryptographic key pairs for locally controlled AIDs. Ensure private keys never leave the controller context. Provide key derivation from salts and management of key indices.
- **Primary files:** `app/habbing.py` (`Hab`, `Habery`), `app/keeping.py` (`Keeper`, `Manager`)
- **Shared kernel dependency:** Event Processing (BC-1) for Kever state lookup; Persistence (BC-4) for encrypted keystore.

---

**BC-3: CESR Encoding**

- **Core responsibility:** Provide typed, self-describing cryptographic primitive objects and serialization/deserialization of all protocol messages. All protocol data enters and exits through CESR-qualified types.
- **Primary files:** `core/coring.py` (`Matter`, `Prefixer`, `Diger`, `Verfer`, `Siger`, `Cigar`, `Seqner`, `Tholder`, `Salter`), `core/counting.py` (`Counter`), `core/indexing.py` (`Siger`/`Indexer`), `core/structing.py`, `core/serdering.py` (`Serder`, `SerderKERI`, `SerderACDC`)
- **Shared kernel dependency:** None. CESR Encoding is foundational; it has no domain-layer dependencies.
- **Shared kernel status:** BC-3 is a **shared kernel** component. All CESR primitive types (`Matter` and subclasses) and message containers (`Serder`, `SerderKERI`, `SerderACDC`) are accessible to all bounded contexts. BC-3 retains type-code schema and codec ownership authority.

---

**BC-4: Persistence**

- **Core responsibility:** Durably store and retrieve key events, key state, witness receipts, escrowed events, endpoint records, and OOBI records using LMDB. Provide indexed access by AID prefix and sequence number.
- **Primary files:** `db/basing.py` (`Baser`), `db/dbing.py` (`LMDBer`), `db/subing.py`, `db/koming.py`, `db/escrowing.py`
- **Shared kernel dependency:** CESR Encoding (BC-3) for serialization of stored records.
- **Shared kernel status:** BC-4 is a **shared kernel** component. `Baser` is the protocol's single durable state store and is accessible to all bounded contexts as a read/write state repository. BC-4 retains sub-table schema definition and ownership authority. Only BC-4 may add new sub-tables to `Baser`; all other BCs access `Baser` through named helper methods on `LMDBer`.

---

**BC-5: Infrastructure Services**

- **Core responsibility:** Enable the indirect trust modality by operating witnesses and watchers, resolving OOBIs, forwarding messages, and providing high-availability promulgation and confirmation networks for AID KELs.
- **Primary files:** `app/agenting.py` (`WitnessReceiptor`, `WitnessInquisitor`, `WitnessPublisher`), `app/indirecting.py`, `app/oobiing.py`, `app/forwarding.py`, `app/watching.py`
- **Shared kernel dependency:** Event Processing (BC-1); Persistence (BC-4); Key Management (BC-2) for locally hosted witnesses.

---

**BC-6: Verifiable Credentials (ACDC)**

- **Core responsibility:** Issue, revoke, and verify ACDC verifiable credentials whose lifecycle is anchored to AID key states via the Verifiable Data Registry (VDR). Validate credential chains, schemas, and revocation status.
- **Primary files:** `vc/protocoling.py`, `vc/walleting.py`, `vdr/` (registry), `acdc/messaging.py`, `core/scheming.py`
- **Shared kernel dependency:** Event Processing (BC-1) for AID key state verification; CESR Encoding (BC-3) for ACDC serialization.

---

**BC-7: Peer Messaging**

- **Core responsibility:** Handle point-to-point authenticated exchange messages (`exn`) between controllers, including IPEX credential exchange protocol, challenge-response authentication, and group multi-sig coordination messages.
- **Primary files:** `peer/exchanging.py`, `app/challenging.py`, `app/grouping.py`, `app/delegating.py`
- **Shared kernel dependency:** Key Management (BC-2) for signing; Event Processing (BC-1) for AID validation; CESR Encoding (BC-3).

---

*End of Phase 1 output. Sections 4–9 to be produced in subsequent phases.*

---

## Section 4 — External Domain Catalog

### 4.1 External Domain Registry

Nine external domains are catalogued below. For each, a **Port** names what keripy needs in domain language, and one or more **Adapters** name the concrete satisfier(s) currently in use.

---

#### ED-1: Cryptographic Signature Primitives

| Field | Value |
|---|---|
| **External Domain** | Cryptographic Signature Primitives (libsodium / PyCA cryptography) |
| **Port Name** | Signing Oracle |
| **Port Concept Description** | keripy needs to produce and verify digital signatures over byte sequences using named algorithm suites (Ed25519, ECDSA/P-256, ECDSA/secp256k1, Ed448), and to derive key material from seeds and passphrases (Argon2 key stretching, X25519 key exchange for encrypted private-key storage). The domain owns algorithm selection — indexed by CESR type codes — and the invariant that a valid signature over an event authorizes a key state change. It does not own the mathematical implementation of any cipher. |
| **Adapter Name(s)** | `pysodium` (libsodium Python bindings — Ed25519 sign/verify, X25519 key derivation, Argon2, `randombytes`); `cryptography` (PyCA hazmat layer — ECDSA P-256, ECDSA secp256k1, Ed448) |
| **Leakage Risk** | **High.** `pysodium` is imported directly in six domain files: `core/coring.py`, `core/signing.py`, `app/keeping.py`, `help/helping.py`, `app/forwarding.py`, `cli/commands/salt.py`. `cryptography.hazmat.*` is imported in `core/coring.py`, `core/signing.py`, `cli/commands/ssh/export.py`. No Signing Oracle port abstraction (ABC/Protocol class) exists. Concrete libsodium and PyCA calls are co-located with domain signing logic inside `core/coring.py` and `core/signing.py`. |

---

#### ED-2: Cryptographic Digest Computation

| Field | Value |
|---|---|
| **External Domain** | Cryptographic Digest Computation (blake3, hashlib) |
| **Port Name** | Digest Oracle |
| **Port Concept Description** | keripy needs to compute deterministic, collision-resistant cryptographic digests of byte sequences using named hash algorithms (Blake3-256, Blake2b-256, SHA-256, SHA3-256, SHA3-512). The domain owns the algorithm selection logic — keyed by CESR type codes that identify the hash suite used for a given Diger — and the invariant that a Diger's `raw` field equals the digest of its `ser` input under the named algorithm. It does not own the hash function implementations. |
| **Adapter Name(s)** | `blake3` Python package (Blake3-256, Blake2b); Python standard library `hashlib` (SHA-256, SHA3-256, SHA3-512, SHA-512) |
| **Leakage Risk** | **High.** `blake3` and `hashlib` are imported and called directly inside `core/coring.py` (`Diger.__init__` and `Diger.verify`). The algorithm dispatch table maps CESR type codes to concrete hash constructors. No Digest Oracle port abstraction exists. |

---

#### ED-3: Durable Key-Value Persistence (LMDB)

| Field | Value |
|---|---|
| **External Domain** | Durable Key-Value Persistence (LMDB) |
| **Port Name** | Durable Event Store |
| **Port Concept Description** | keripy needs to durably append, index, and retrieve ordered byte sequences keyed by composite domain identifiers (AID prefix + sequence number; AID prefix + digest). It needs atomic multi-key writes, ordered prefix-scan iteration, and the ability to open isolated read transactions alongside concurrent write transactions. The domain owns the key schema and the semantics of stored records (what each database sub-table means in KERI terms). It does not own the storage engine, file format, or transaction management protocol. |
| **Adapter Name(s)** | `lmdb` Python package (Lightning Memory-Mapped Database) via `db/dbing.py` (`LMDBer`), `db/basing.py` (`Baser`), `db/koming.py` (`Komer`) |
| **Leakage Risk** | **Medium.** `lmdb` imports are confined to the three files above — the `db/` directory functions as a de-facto adapter boundary. However, `LMDBer` exposes LMDB `Transaction` and `Cursor` objects through its helper methods, and LMDB environment/database-handle setup logic is embedded in domain-named classes. No `Dber` port abstraction (ABC) exists — the V02 violation recorded in project memory — so there is no clean interface for substituting an alternative storage engine. |

---

#### ED-4: HTTP/TCP Transport (falcon + hio networking)

| Field | Value |
|---|---|
| **External Domain** | HTTP and TCP Network Transport (Falcon, hio.core.http, hio.core.tcp) |
| **Port Name** | Protocol Message Channel |
| **Port Concept Description** | keripy needs to receive KERI protocol messages addressed to its HTTP endpoints (witness endpoints, mailbox endpoints, OOBI resolution endpoints) and to dispatch outbound KERI protocol messages to remote HTTP endpoints by AID-resolved URL. The domain owns the message routing logic, the URL-to-AID resolution semantic, and KERI message format. It does not own the HTTP wire protocol, socket lifecycle, WSGI/ASGI request dispatch, or TCP connection pooling. |
| **Adapter Name(s)** | `falcon` (HTTP routing, request/response abstraction, WSGI/ASGI app); `hio.core.http` (`ClientHttper`, `ServerHttper`, HTTP Doers); `hio.core.tcp` (`Server`, `Client` TCP socket Doers) |
| **Leakage Risk** | **Medium.** `falcon` and `hio.core.http/tcp` are confined to `app/httping.py`, `app/agenting.py`, `app/indirecting.py`, `app/signaling.py`, `app/oobiing.py`, `end/ending.py`, `app/specing.py`. These are infrastructure-adjacent files. However, Falcon `Request`/`Response` types appear as parameters to domain-logic handler methods in `end/ending.py`, coupling domain message dispatch to the Falcon type system. No Protocol Message Channel port abstraction exists. |

---

#### ED-5: Cooperative Task Orchestration (hio)

| Field | Value |
|---|---|
| **External Domain** | Cooperative Task Orchestration (hio) |
| **Port Name** | Asynchronous Task Scheduler |
| **Port Concept Description** | keripy needs to run multiple long-lived, interleaved protocol processing tasks concurrently — witness receipt cycling, escrow re-evaluation, OOBI resolution retries, mailbox polling — without blocking I/O or OS threads. The domain expresses each task as a named, suspendable unit of work. It does not own the coroutine scheduling algorithm, the task lifecycle (start/stop/abort), or the message queue implementation. |
| **Adapter Name(s)** | `hio.base.doing` (`Doer` base class, generator coroutine protocol, `doize()` helper); `hio.help.decking` (`Deck` FIFO message queue); `hio.base.filing` (file/directory lifecycle management via `Filer`) |
| **Leakage Risk** | **High.** `from hio` imports are found in 124 source files — virtually the entire `app/`, `core/`, `db/`, `vdr/`, `vc/`, `peer/`, `cli/`, and `demo/` layers. The hio `Doer` generator pattern is the structural scaffold for all domain task classes (`Kevery`, `WitnessReceiptor`, `OobiResolver`, etc.). This makes the external orchestration framework an implicit structural constraint on domain class design throughout the codebase. No Asynchronous Task Scheduler port abstraction exists. |

---

#### ED-6: Generic Message Serialization (JSON / CBOR / MsgPack)

| Field | Value |
|---|---|
| **External Domain** | Generic Message Serialization (JSON, CBOR, MsgPack) |
| **Port Name** | Serialization Format Codec |
| **Port Concept Description** | keripy needs to serialize event body dictionaries and ACDC data containers to and from three interchangeable wire formats: JSON text (human-readable, default), CBOR binary (compact), and MsgPack binary (alternative compact). The domain owns the event schema, the field label conventions, and the CESR `kind` code that selects the active format. It does not own the encoding/decoding algorithm for any of the three formats. |
| **Adapter Name(s)** | Python standard library `json`; `cbor2` Python package; `msgpack` Python package |
| **Leakage Risk** | **Medium.** Format dispatch is substantially centralized in `core/serdering.py` (`Serder.loads`, `Serder.dumps`), which is the intended codec boundary. However, `cbor2` and `msgpack` are also imported directly in `core/scheming.py` and `app/configing.py`, bypassing the Serder codec layer. `json` is imported in numerous files throughout `app/`, `core/`, and `cli/` for ad-hoc dict serialization outside of Serder. |

---

#### ED-7: JSON Schema Validation (jsonschema)

| Field | Value |
|---|---|
| **External Domain** | JSON Schema Validation (jsonschema) |
| **Port Name** | Credential Schema Validator |
| **Port Concept Description** | keripy needs to validate that ACDC credential attribute data conforms to a SAID-indexed JSON Schema document. The domain owns the schema registry, the SAID-based schema lookup, and the semantic that an ACDC whose attributes fail schema validation is not issuable. It does not own the JSON Schema draft specification or the validation algorithm. |
| **Adapter Name(s)** | `jsonschema` Python package |
| **Leakage Risk** | **Low.** `jsonschema` is imported in one file only: `core/scheming.py`. The `Schemer` class wraps it, providing a domain-named interface. No formal Credential Schema Validator port abstraction (ABC) exists, but the usage is well-contained. |

---

#### ED-8: HTTP Structured Fields / HTTP Signature Header Codec (http_sfv)

| Field | Value |
|---|---|
| **External Domain** | HTTP Structured Fields (IETF RFC 8941) |
| **Port Name** | HTTP Signature Header Codec |
| **Port Concept Description** | keripy needs to serialize and parse HTTP Signature Field Values per RFC 8941 Structured Fields to implement the HTTP Signatures authentication protocol on KERIA API endpoints. The domain owns the signing key selection logic, the KERI AID-to-key resolution for signature verification, and the invariant that an HTTP request with an invalid or missing `Signature` header must be rejected. It does not own the RFC 8941 structured field grammar or parsing algorithm. |
| **Adapter Name(s)** | `http_sfv` Python package |
| **Leakage Risk** | **Low.** `http_sfv` is imported in one file only: `end/ending.py`. The `Httper` class and endpoint helpers in that file centralize all HTTP signature operations. |

---

#### ED-9: Configuration File Parsing (hjson)

| Field | Value |
|---|---|
| **External Domain** | Configuration File Parsing (HJSON) |
| **Port Name** | Configuration Source |
| **Port Concept Description** | keripy needs to read operator-provided configuration from files, where the files may include human-authored comments and relaxed JSON syntax (HJSON format). The domain owns the configuration schema (what fields are valid, their defaults, and their effect on AID lifecycle behavior). It does not own the file format parser or the I/O path to the configuration file. |
| **Adapter Name(s)** | `hjson` Python package; Python standard library `json` (fallback for strict JSON config files) |
| **Leakage Risk** | **Low.** `hjson` is imported in one file only: `app/configing.py`. The `Configer` class wraps the file-parsing logic. |

---

### 4.2 Leakage Checklist

These five checks assess the current state of keripy's boundary hygiene against the classification system's leakage detection rules (Section 10.1 of the classification system).

---

**Check 1 — No external domain type names appear in domain specs**

| Status | FAIL |
|---|---|
| **Evidence** | Section 3.3 of this specification (produced in Phase 1) explicitly names "LMDB" in BC-4's core responsibility ("using LMDB"), in BC-4's primary files list (`db/dbing.py (LMDBer)`), and in the shared kernel dependency cross-reference from BC-1 and BC-2. The spec describes the persistence bounded context in terms of its concrete storage adapter rather than the abstract port concept ("Durable Event Store"). This makes the spec itself a leakage artifact. |
| **Rule Violated** | "Spec describes 'what' and 'why', never 'how'" — the BC-4 description violates this by stating the storage engine. |

---

**Check 2 — No external domain imports appear in domain logic files**

| Status | FAIL |
|---|---|
| **Evidence** | External library imports appear in core domain logic files with no port abstraction layer between them and the domain: `pysodium` in `core/coring.py` (signing/verification inside CESR primitive objects), `blake3` in `core/coring.py` (digest computation inside `Diger`), `cryptography.hazmat.*` in `core/coring.py` and `core/signing.py`, `pysodium` in `app/keeping.py` (private key encryption/decryption in key manager). `from hio` appears in 124 files across all layers. |
| **Affected external domains** | ED-1 (Signing), ED-2 (Digest), ED-5 (Orchestration) |

---

**Check 3 — Port abstractions use only domain-language types**

| Status | FAIL |
|---|---|
| **Evidence** | No port abstractions (Python `ABC` or `Protocol` classes) exist for any of the nine external domains catalogued. The `Dber` abstract base class for the Durable Event Store port is absent — this is the V02 violation recorded in project memory. Without port abstractions, the question of whether they use domain-language types is moot: the domain calls external APIs directly everywhere. The closest approach to a port boundary is `core/serdering.py`'s `Serder` class for ED-6, but it is not formally declared as a port interface. |

---

**Check 4 — Adapter files are the only files touching external domain APIs**

| Status | FAIL |
|---|---|
| **Evidence** | No files are designated as adapters. The following external APIs are called outside any single-file boundary: `pysodium` across 6 files; `from hio` across 124 files; `falcon` across 6 app-layer files; `cbor2`/`msgpack` across at least 4 files. The only near-compliant case is `lmdb`, which is confined to 3 files all within `db/`, making `db/` a de facto adapter boundary — but it is not formally declared as such and the files within it contain domain-specific logic alongside adapter logic. |

---

**Check 5 — Specs describe "what" and "why", never "how"**

| Status | FAIL |
|---|---|
| **Evidence** | The KERI protocol specification (Trust Over IP) correctly describes "what" and "why" without naming implementation technologies. However, keripy's own internal architecture documentation (including Section 3.3 of this DDD specification) leaks "how" at every persistence and transport reference. BC-4 says "using LMDB"; BC-1 and BC-2 reference "LMDB database" in their shared kernel descriptions. The `CLAUDE.md` repository overview explicitly names LMDB, Falcon, and hio as implementation facts. These are correct observations about the current state — the point is that no spec layer within keripy distinguishes the port concept from its concrete adapter. |

---

**Leakage Summary**

| Check | Status | Primary Offenders |
|---|---|---|
| 1. No external type names in domain specs | **FAIL** | "LMDB" in BC-4 description; adapter names in BC primary file lists |
| 2. No external imports in domain logic files | **FAIL** | `pysodium`/`blake3`/`cryptography` in `core/coring.py`; `hio` in 124 files |
| 3. Port abstractions use domain-language types | **FAIL** | No port abstractions exist; `Dber` ABC absent (V02) |
| 4. Only adapter files touch external APIs | **FAIL** | No designated adapter files; external calls throughout domain layers |
| 5. Specs describe what/why, never how | **FAIL** | BC-4, BC-1, BC-2 descriptions name LMDB and other concrete technologies |

All five checks fail. This is consistent with keripy's status as a pragmatic reference implementation built without a hexagonal (ports-and-adapters) architecture. The DDD gap between the current state and the target architecture is substantial and is formally recorded here for Phase 5 (Violation Inventory) and Phase 8 (Gap Analysis).

---

*End of Phase 2 output. Sections 5–9 to be produced in subsequent phases.*

---

## Section 5 — Concept Registry

### 5.1 Classification Overview

Concepts are drawn from all seven bounded contexts identified in Section 3.3. Classification applies three axes: Centrality (`core` | `peripheral` | `external`), Weight (`trivial` | `non-trivial` | `substantive` | `complex`), and Structure (`atomic` | `composite`). Disposition records the recommended treatment for each concept. Spec Coverage indicates whether the concept is named/described in the KERI, CESR, or ACDC specifications (`spec`), is implied but not named (`partial`), or exists only in keripy source (`code-only`).

---

### 5.2 Concept Registry Table

#### BC-1 — Event Processing

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Key Event | core | substantive | composite | implement | spec | `core/eventing.py` | Six ilks: icp, rot, ixn, dip, drt, rct. Assembles SerderKERI + Siger list + Prefixer + Seqner. |
| Key Event Log (KEL) | core | complex | composite | implement | spec | `db/basing.py` | Append-only backward-chained ordered sequence per AID. Stored as multi-index LMDB sub-tables in Baser. |
| KERL (Key Event Receipt Log) | core | substantive | composite | implement | spec | `db/basing.py` | KEL augmented with witness receipts. Receipt quorum enforced by TOAD. Baser stores receipts separately and joins at query time. |
| Kever (Key State) | core | complex | composite | dark | code-only | `core/eventing.py:1586` | Runtime in-memory fully verified key state for one AID. Spec calls this "key state" without naming the class. |
| Kevery (Event Processing Facility) | core | complex | composite | dark | code-only | `core/eventing.py:3776` | Kever factory and message processing pipeline. Owns nine typed escrow buckets and a Cue dispatcher. |
| Pre-rotation | core | complex | atomic | implement | spec | `core/eventing.py` | Invariant: next rotation must satisfy the ndigers commitment made in the prior establishment event. Enforced in `Kever.update()`. |
| Signing Threshold (Tholder) | core | substantive | atomic | implement | spec | `core/coring.py:4346` | M-of-N or weighted fractional signing requirement. Both simple integer and list-of-fractions forms. |
| Duplicity | core | substantive | atomic | implement | spec | `core/eventing.py` | Condition: two conflicting events at same sequence number. Raises `LikelyDuplicitousError`; events land in LDE escrow. |
| Seal | core | non-trivial | atomic | implement | spec | `core/structing.py` | Seven namedtuple variants: SealDigest, SealRoot, SealSource, SealEvent, SealLast, SealBack, SealKind. |
| Escrow | core | substantive | composite | implement | partial | `db/escrowing.py`, `core/eventing.py` | Nine named escrow buckets in Kevery (OOE, PSE, PWE, LDE, UWE, URE, VRE, KSN, QNF). Spec implies deferred processing but does not name the mechanism. |
| Inception Event (icp) | core | substantive | composite | implement | spec | `core/eventing.py` | Establishes AID. Derives prefix from initial public key or event SAID. Initializes witness pool and pre-rotation commitment. |
| Delegated Inception (dip) | core | substantive | composite | implement | spec | `core/eventing.py` | icp variant requiring delegator anchor seal in a concurrent interaction or rotation event. |
| Rotation Event (rot) | core | substantive | composite | implement | spec | `core/eventing.py` | Transfers control to new key set. Must satisfy prior ndigers commitment. Optionally changes witness pool. |
| Delegated Rotation (drt) | core | substantive | composite | implement | spec | `core/eventing.py` | rot variant requiring delegator anchor. Validates `delpre` on Kever. |
| Interaction Event (ixn) | core | non-trivial | atomic | implement | spec | `core/eventing.py` | Non-establishment event. Anchors external seals without changing key material. Extends KEL chain. |
| Receipt (rct) | core | non-trivial | atomic | implement | spec | `core/eventing.py` | Witness countersignature on a key event. Stored as indexed Siger in Baser receipt sub-tables. |
| KAWA / Witness Quorum | core | complex | atomic | implement | spec | `core/eventing.py` | BFT quorum mathematics for TOAD. Implemented as `ample()` and `simple()` functions. No named class. |
| Delegation | core | complex | composite | implement | spec | `app/delegating.py`, `app/grouping.py` | Hierarchical AID authority grant. Requires synchronized anchor between delegatee and delegator KELs. |
| TOAD (Threshold of Accountable Duplicity) | core | non-trivial | atomic | implement | spec | `core/eventing.py` | Integer quorum threshold stored on Kever as `toader`. Computed from `ample()`/`simple()` at establishment events. |

---

#### BC-2 — Key Management

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Hab (Habitat) | core | complex | composite | dark | code-only | `app/habbing.py:2166` | keripy controller context for one locally managed AID. Bundles Kever, Manager, Baser, Kevery, Parser. |
| Habery (Habitat Registry) | core | substantive | composite | dark | code-only | `app/habbing.py:111` | Shared environment owning Baser + Keeper across all local Habs. Entry point for all local AID operations. |
| GroupHab (Multi-sig Habitat) | core | complex | composite | dark | code-only | `app/habbing.py` | Hab variant for group (multi-sig) controlled AIDs. Tracks partial-sig collection and participant Habs. |
| Manager (Key Manager) | core | complex | composite | dark | code-only | `app/keeping.py:594` | Generates, encrypts, stores, and rotates private key material. Never exposes raw private keys outside this class. |
| Keeper (Keystore) | core | substantive | composite | dark | code-only | `app/keeping.py:133` | Encrypted LMDB database for private key material. Stores PreSit (key situation) and PrePrm (derivation params) per AID. |
| Salter (Key Derivation) | core | substantive | atomic | implement | partial | `core/signing.py:329` | Deterministic hierarchical key derivation from a root salt via pidx+ridx+kidx index triplet. Argon2-stretched for production tiers. |
| AID / Prefixer | core | substantive | atomic | implement | spec | `core/coring.py:3723` | Self-certifying identifier. Derivable as basic (public key hash) or self-addressing (event SAID). `Prefixer.verify()` enforces derivation invariant. |
| Key Algorithm (Algos) | peripheral | trivial | atomic | implement | partial | `app/keeping.py` | Named enum: `salty` (deterministic from salt), `randy` (random), `group` (multisig), `extern` (external HSM). |
| Security Tier (Tierage) | peripheral | trivial | atomic | implement | partial | `core/signing.py` | Named enum controlling Argon2 stretch intensity: `low` (test), `med` (default), `high` (production). |
| PubLot / PreSit | peripheral | non-trivial | composite | dark | code-only | `app/keeping.py` | Dataclass pair tracking old/new/nxt public key sets with rotation index and key index. Persistence record for Manager state. |

---

#### BC-3 — CESR Encoding

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Matter (CESR Primitive Base) | core | complex | atomic | implement | spec | `core/coring.py:689` | Base class for all typed CESR primitives. Owns base-64 ↔ binary codec, type code tables, variable-length lead-byte encoding. |
| Verfer (Verification Key) | core | non-trivial | atomic | implement | spec | `core/coring.py:3409` | CESR-typed public key. `verify()` dispatches to correct algorithm (Ed25519, ECDSA, Ed448) by code prefix. |
| Diger (Digest) | core | non-trivial | atomic | implement | spec | `core/coring.py:3584` | CESR-typed cryptographic digest. Algorithm dispatch by type code. `verify()` recomputes and compares. |
| Siger (Indexed Signature) | core | non-trivial | atomic | implement | spec | `core/indexing.py:741` | CESR-typed signature with signing-key index into current key list. Extends `Indexer`. |
| Cigar (Non-indexed Signature) | core | non-trivial | atomic | implement | spec | `core/coring.py` | CESR-typed signature without index. Used for non-transferable signers (witnesses, watchers). |
| Seqner (Sequence Number) | core | trivial | atomic | implement | spec | `core/coring.py:1577` | CESR-typed sequence number. Fixed 22-char base-64 representation. Used in all event, receipt, and state records. |
| Counter (CESR Attachment Counter) | core | non-trivial | atomic | implement | spec | `core/counting.py:394` | CESR group composition code. Two-version codex (1.0 / 2.0). Counts and delimits attachment groups (signature lists, seal lists). |
| Tholder (Threshold) | core | substantive | atomic | implement | spec | `core/coring.py:4346` | M-of-N or weighted signing threshold. Integer form `n` or list-of-fractions form. `satisfy()` evaluates whether a set of signers meets threshold. |
| Prefixer | core | substantive | atomic | implement | spec | `core/coring.py:3723` | CESR-typed AID prefix. Derives and verifies AID according to basic, self-addressing, or self-signing derivation rules. |
| SAID (Self-Addressing Identifier) | core | substantive | atomic | implement | spec | `core/coring.py` | Content-addressable identifier embedded in its own data structure. Computed via placeholder substitution + digest + re-embed. |
| Serder (Event Message Container) | core | substantive | composite | implement | spec | `core/serdering.py:231` | Protocol-aware container for KERI/ACDC messages. Owns SAD integrity verification, SAID computation, version string parse. Subclasses: SerderKERI, SerderACDC. |
| Salter | core | substantive | atomic | implement | partial | `core/signing.py:329` | (Cross-listed; see BC-2 Manager.) |
| Version String / Versionage | peripheral | non-trivial | atomic | implement | spec | `core/kering.py` | Embedded wire-format version string parsed by Serder. Encodes protocol, version, serialization kind, and message size. |

---

#### BC-4 — Persistence

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Baser (KERI Event Database) | core | complex | composite | dark | code-only | `db/basing.py:164` | Comprehensive LMDB event database. Owns 50+ named sub-tables for events, key state, receipts, escrows, endpoints, OOBIs, contacts. |
| LMDBer (LMDB Base Adapter) | peripheral | substantive | composite | port | code-only | `db/dbing.py` | Raw LMDB operations. Should be behind `Dber` ABC (absent — V02 violation). Currently the sole concrete satisfier of the Durable Event Store port. |
| Dber ABC (Durable Event Store port) | external | substantive | atomic | absent | code-only | [not implemented] | Named port abstraction for storage substitutability. Recorded as V02 violation. No `ABC` or `Protocol` class exists. |
| Komer (Typed Record Sub-table) | peripheral | non-trivial | atomic | implement | code-only | `db/koming.py` | Generic typed LMDB sub-table wrapper. Maps domain keys to dataclass records via JSON serialization. |
| KeyStateRecord | core | non-trivial | atomic | implement | partial | `recording.py` | Persisted snapshot of a Kever's key state. Used to reconstruct Kever on cold start without replaying full KEL. |
| OobiRecord | peripheral | non-trivial | atomic | implement | code-only | `recording.py` | Persisted OOBI resolution state: URL, AID, role, resolved status, datetime. |
| EndpointRecord | peripheral | non-trivial | atomic | implement | partial | `recording.py` | Persisted endpoint role/scheme/location triple for an AID. Input to OOBI and witness contact. |

---

#### BC-5 — Infrastructure Services

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Witness | core | complex | composite | implement | spec | `app/agenting.py` | Infrastructure node that receipts key events, exchanges receipts with peer witnesses, and applies KAWA quorum. Assembles WitnessReceiptor + WitnessPublisher + WitnessInquisitor. |
| Watcher | core | substantive | composite | implement | spec | `app/watching.py` | Infrastructure node that enforces first-seen policy and detects duplicity for watched AIDs. Not declared in KEL; confidential to validator. |
| OOBI (Out-of-Band Introduction) | core | substantive | composite | implement | spec | `app/oobiing.py` | Bootstrap URL + AID pair for endpoint discovery. Resolution pipeline: fetch → parse → validate → store OobiRecord. |
| Mailbox | peripheral | non-trivial | composite | implement | partial | `app/storing.py` | Asynchronous topic-keyed message queue for indirect-mode event delivery. Enables offline witnesses and multi-sig coordination. |
| WitnessReceiptor | core | non-trivial | composite | dark | code-only | `app/agenting.py` | Doer that collects and sends event receipts to witnesses. Subcomponent of Witness infrastructure. |
| WitnessPublisher | core | non-trivial | composite | dark | code-only | `app/agenting.py` | Doer that publishes completed receipts to witnesses and monitors receipt accumulation. |
| WitnessInquisitor | core | non-trivial | composite | dark | code-only | `app/agenting.py` | Doer that queries witnesses to retrieve missing receipts during escrow processing. |

---

#### BC-6 — Verifiable Credentials (ACDC)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| ACDC (Authentic Chained Data Container) | core | complex | composite | implement | spec | `vdr/credentialing.py`, `vc/` | SAID-identified, schema-validated verifiable credential anchored to issuer AID key state. Supports chaining via `e` (edge) field. |
| VDR / TEL (Transaction Event Log) | core | complex | composite | implement | spec | `vdr/eventing.py`, `vdr/viring.py` | Credential registry with its own append-only event log. Parallel structure to KEL: vcp (registry inception), iss (issuance), rev (revocation). |
| Regery (Registry Manager) | core | substantive | composite | dark | code-only | `vdr/credentialing.py` | keripy-specific registry context analogous to Habery. Owns Reger + Tevery + credential wallet. |
| Reger (Registry Database) | core | non-trivial | composite | dark | code-only | `vdr/viring.py` | LMDB database for TEL events, registry states, credential states, and TSN escrows. Parallel to Baser for credential domain. |
| Tevery (TEL Event Processor) | core | substantive | composite | dark | code-only | `vdr/eventing.py` | TEL event validation processor. Parallel to Kevery for TEL events. Enforces vcp→iss/rev chaining. |
| Schemer (Credential Schema) | core | non-trivial | composite | implement | spec | `core/scheming.py` | JSON Schema document identified by SAID. Cached in Baser. `Schemer.verify()` validates ACDC attribute block against schema. |
| IPEX (Issuance and Presentation Exchange) | core | complex | composite | implement | spec | `vc/protocoling.py` | Six-step credential negotiation protocol over `exn` messages: apply → offer → agree → grant → admit / spurn. |

---

#### BC-7 — Peer Messaging

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| EXN (Exchange Message) | core | substantive | composite | implement | spec | `peer/exchanging.py` | Peer-to-peer authenticated `exn` message envelope. Assembles Exchanger router + handler registry + route dispatch + exn Serder. |
| Exchanger (EXN Router) | core | substantive | composite | dark | code-only | `peer/exchanging.py:24` | Routes incoming `exn` messages to registered handlers by route path. Manages partial-sig escrow for exchange messages. |
| Challenge-Response | peripheral | non-trivial | atomic | implement | partial | `app/challenging.py` | Peer authentication: sender signs random word list, receiver validates signed response against AID key state. |
| Counselor (Multisig Coordinator) | core | complex | composite | dark | code-only | `app/grouping.py:19` | Coordinates partially-signed group multisig events. Orchestrates: partial-sig escrow + delegation anchor + witness receipt collection. |
| Anchorer (Delegation Anchor Doer) | core | substantive | composite | dark | code-only | `app/delegating.py:20` | Sends delegation events to delegator and waits for the delegator anchor to appear in the KEL before completing. |
| Notifier | peripheral | trivial | atomic | implement | code-only | `app/notifying.py` | Persistent notification queue for controller-facing events (credential grants, OOBI resolutions, challenge results). |

---

### 5.3 Concept Cards

A concept card is written for every concept classified as `core + complex` (at any structure) and for every `composite` concept (at any centrality or weight). Cards are ordered by bounded context.

---

#### BC-1: Event Processing

---

**Key Event**
- Axes: core | substantive | composite
- A key event is a signed, CESR-serialized message that either establishes (`icp`, `dip`), updates (`rot`, `drt`), or extends (`ixn`, `rct`) the state of exactly one AID; its domain invariant is that no event is valid without satisfying the signature threshold of the current key state and being correctly chained to the prior event by digest. It assembles a `SerderKERI` body, a list of `Siger` indexed signatures, a `Prefixer` for the AID, and a `Seqner` for ordering.

---

**Key Event Log (KEL)**
- Axes: core | complex | composite
- The KEL is the authoritative, append-only, backward-chained sequence of all key events for a single AID; its invariant is that every event at sequence number `n` must contain the digest of event `n-1`, making retrospective tampering detectable. It is assembled from individual Key Event records stored across multiple indexed LMDB sub-tables in `Baser` (keyed by `dgKey` = prefix+digest and `snKey` = prefix+sn), plus the first-seen ordinal index.

---

**KERL (Key Event Receipt Log)**
- Axes: core | substantive | composite
- The KERL extends the KEL by augmenting each event with signed receipts from the designated witness pool; its invariant is that a controller operating in indirect mode is not considered to have published an event until the event accumulates receipts from at least TOAD witnesses. It assembles the KEL (events in `Baser.evts`) with the witness receipt sub-tables (`Baser.wigs`, `Baser.rcts`) and applies the `ample()`/`simple()` quorum check.

---

**Kever (Key State)**
- Axes: core | complex | composite
- Kever is keripy's runtime in-memory representation of the fully verified, current key state of one AID; its invariants are that it is only created or updated by a `Kevery` instance that has successfully verified all signature thresholds, chaining digests, pre-rotation commitments, and (for delegated AIDs) delegator anchor seals. It assembles `Prefixer`, `Verfer` list, `Tholder` (current threshold), `ndigers` (next key digest list), `Tholder` (next threshold), `Seqner`, `wits` list, `TOAD`, `delegated` flag, and `delpre`.

---

**Kevery (Event Processing Facility)**
- Axes: core | complex | composite
- Kevery is the KERI message processing pipeline that acts as a `Kever` factory: it ingests parsed event streams, validates each event, creates or updates Kevers, and routes events that cannot yet be applied into one of nine typed escrow buckets (OOE, PSE, PWE, LDE, UWE, URE, VRE, KSN, QNF). Its invariants include that every escrow bucket has a named timeout and that no non-idempotent database write occurs for an event that fails validation.

---

**Pre-rotation**
- Axes: core | complex | atomic
- Pre-rotation is the security mechanism by which an establishment event commits to the cryptographic digest(s) of the next signing key set, so that only the party holding the pre-committed keys can execute the subsequent rotation; the invariant is that `rot.keys[i]` must hash under the declared algorithm to one of the `ndigers` committed in the prior establishment event, and any rotation event failing this check is unconditionally rejected by `Kever.update()`.

---

**KAWA / Witness Quorum**
- Axes: core | complex | atomic
- KAWA (KERI's Algorithm for Witness Agreement) is the Byzantine-fault-tolerant quorum computation that determines the minimum number of witness receipts required to consider a key event promulgated; the invariants are that for `n` witnesses with fault tolerance `f`, the quorum `m` satisfies `(n+f+1)/2 ≤ m ≤ n-f`, implemented as `ample(n, f, weak)` and `simple(n)` in `core/eventing.py`, and called against `Kever.toader` at event validation time.

---

**Delegation**
- Axes: core | complex | composite
- Delegation is the hierarchical authority grant by which a delegator AID endorses the inception or rotation of a delegatee AID by embedding an anchor seal in a concurrent event; its invariant is that a delegated inception (`dip`) or rotation (`drt`) is not valid until the delegator's KEL contains an event with a `SealEvent` pointing to the delegatee event's SAID, enforced by the `Anchorer` Doer coordinating via the delegation partial-witness escrow.

---

**Escrow**
- Axes: core | substantive | composite
- Escrow is the deferred-processing subsystem that holds key events and receipts whose prerequisite data (prior events, sufficient signatures, delegation anchor, witness quorum) has not yet arrived; it assembles nine named LMDB IoSet sub-tables in `Kevery` plus the `db/escrowing.py` `Broker` for TEL state notices, each with independent timeout logic and a named `processEscrow*` method that re-evaluates stored events when new data becomes available.

---

**Inception Event (icp / dip)**
- Axes: core | substantive | composite
- An inception event establishes an AID by specifying the initial signing key list, the signing threshold, the next-key digest list, the witness pool, and configuration traits; its invariant is that the event SAID (or initial public key) deterministically derives the AID prefix, making the identifier self-certifying, and this derivation is verified by `Prefixer.verify()` before `Kever.__init__()` applies it.

---

**Rotation Event (rot / drt)**
- Axes: core | substantive | composite
- A rotation event transfers control of an AID to a new signing key set by satisfying the pre-rotation commitment (ndigers) from the prior establishment event, optionally modifying the witness pool (cuts and adds), and committing new next-key digests; it assembles: pre-rotation proof verification, new `Verfer` list, updated `Tholder`, new `ndigers`, `cuts`/`adds` witness delta, and a `SealEvent` for the delegator (drt only).

---

---

#### BC-2: Key Management

---

**Hab (Habitat)**
- Axes: core | complex | composite
- Hab is keripy's code-layer controller context for a single locally managed AID: it assembles the AID's `Kever`, a reference to `Habery`'s shared `Baser` and `Manager`, a dedicated `Kevery` and `Parser`, and convenience methods for constructing and signing events (`makeOwnEvent`, `sign`); its invariant is that private key material is only accessible through the `Manager` within Hab's own process, never serialized or transmitted.

---

**Habery (Habitat Registry)**
- Axes: core | substantive | composite
- Habery is the shared environment owner that provides a single `Baser` (event database), a single `Keeper` (keystore), and a `Manager` across all local `Hab` instances; it assembles those resources at construction and exposes factory methods (`makeHab`, `habByName`, `habByPre`) that create or retrieve `Hab` instances, enforcing that all Habs within one Habery share the same encrypted keystore.

---

**GroupHab (Multi-sig Habitat)**
- Axes: core | complex | composite
- GroupHab is a `Hab` subclass for group (multi-sig) controlled AIDs where no single participant holds a sufficient signing threshold alone; it assembles references to the participant Habs (local and remote), the group `Prefixer`, the multi-sig `Tholder`, and partial-signature collection state, and its invariant is that any group event must collect signatures from enough participants to satisfy the threshold before it is submitted to witnesses.

---

**Manager (Key Manager)**
- Axes: core | complex | composite
- Manager is the authority over all private key operations for locally controlled AIDs: it derives new key pairs from salt + index triplets (via `Salter`), encrypts private keys with the controller's AEID-derived symmetric key before storing them in `Keeper`, and decrypts them only transiently to produce signatures; its invariant is that raw private key bytes never persist unencrypted and are zeroed from memory after use.

---

**Keeper (Keystore)**
- Axes: core | substantive | composite
- Keeper is the encrypted LMDB sub-database that persists the private key situation (`PreSit`) and derivation parameters (`PrePrm`) per AID prefix; it assembles three LMDB sub-tables (`pubs`, `pris`, `sits`) keyed by prefix + rotation index, and its invariant is that stored private keys are always AES-encrypted under the manager's decryption key derived from the controller's AEID salt.

---

---

#### BC-3: CESR Encoding

---

**Matter (CESR Primitive Base)**
- Axes: core | complex | atomic
- Matter is the base codec for all typed CESR primitives: it owns the complete type-code tables (MtrDex), the base-64 ↔ binary conversion including lead-byte padding, and the size/type dispatch for both fixed-size and variable-length codes; its invariant is that every `Matter` instance is self-describing — the type of the primitive (key, digest, signature, etc.) and its raw byte length are always recoverable from the leading characters of the qualified base-64 string.

---

**Serder (Event Message Container)**
- Axes: core | substantive | composite
- Serder is keripy's protocol-aware message container that couples a raw serialized event to its deserialized field dict; it assembles the CESR `Kinds` codec (JSON/CBOR/MsgPack), SAID computation (placeholder + digest + embed), SAD integrity verification, and version-string parsing, and its invariant is that `serder.said` always equals the Blake3-256 digest of the event body with the `d` field replaced by a blank filler.

---

---

#### BC-4: Persistence

---

**Baser (KERI Event Database)**
- Axes: core | complex | composite
- Baser is keripy's comprehensive event database that assembles 50+ named LMDB sub-tables covering: key events (by digest and by sequence number), first-seen ordinals, witness receipts (indexed and non-indexed), key state records, escrow buckets, OOBI records, endpoint records, contacts, schema cache, multisig escrows, and migration version; its invariant is that all KERI state that must survive process restart is durably stored here, and all sub-table keys follow the `dgKey`/`snKey` composite-key convention.

---

**LMDBer (LMDB Base Adapter)**
- Axes: peripheral | substantive | composite
- LMDBer wraps raw LMDB environment, database-handle, and transaction management for the keripy database layer; it should be treated as the concrete adapter satisfying the `Durable Event Store` port, but no `Dber` ABC exists to formalize this relationship (V02 violation), leaving LMDB internals (Cursor, Transaction objects) exposed through its helper methods.

---

---

#### BC-5: Infrastructure Services

---

**Witness**
- Axes: core | complex | composite
- A Witness is an infrastructure node designated in a controller's KEL that assembles three collaborating Doers: `WitnessReceiptor` (collects and sends receipts), `WitnessPublisher` (accumulates receipts and evaluates TOAD quorum), and `WitnessInquisitor` (queries peer witnesses for missing receipts); its invariant is that a witness must not publish a receipt for an event that it has not independently verified, and it runs its own `Kevery` to validate incoming events.

---

**Watcher**
- Axes: core | substantive | composite
- A Watcher assembles a `Kevery` in validator mode, a query interface for polling watched AID KELs from witnesses, and a duplicity-detection log; its invariant is that it enforces the first-seen rule — once a Watcher has observed event `n` for an AID, it rejects any conflicting event at the same sequence number — and it stores duplicity evidence for auditing.

---

**OOBI (Out-of-Band Introduction)**
- Axes: core | substantive | composite
- An OOBI assembles a resolvable URL, an AID, an optional role (`witness`, `watcher`, `controller`, `agent`), and an `OobiRecord`; the resolution pipeline fetches the URL, parses the response for a key event stream, validates it via `Kevery`, updates `EndpointRecord` and `OobiRecord` in `Baser`, and emits a resolution cue; its invariant is that an OOBI resolves only when the response contains a valid, verifiable key event stream for the stated AID.

---

**Mailbox**
- Axes: peripheral | non-trivial | composite
- Mailbox assembles a topic-keyed persistent LMDB queue (`Baser.mbx`) and delivery-tracking index; it enables asynchronous indirect-mode message delivery (multi-sig coordination, delegation requests, IPEX messages) to AIDs whose controllers may not be continuously online.

---

---

#### BC-6: Verifiable Credentials (ACDC)

---

**ACDC (Authentic Chained Data Container)**
- Axes: core | complex | composite
- An ACDC assembles a `SerderACDC` body (SAID-identified, schema-validated credential data), an issuer AID key state reference, a `SealEvent` anchor in the issuer's KEL at the time of issuance, and an optional edge list for credential chaining; its invariant is that the ACDC SAID must be derivable from the body content, the issuer's key state at the anchoring sequence number must be verifiable, and the schema SAID must resolve to a valid JSON Schema document.

---

**VDR / TEL (Transaction Event Log)**
- Axes: core | complex | composite
- The VDR / TEL is a credential registry with its own append-only event log parallel to a KEL: it assembles a `vcp` (registry inception), `iss` (credential issuance), and `rev` (credential revocation) event sequence, each anchored via seal to the issuer's KEL; its invariant is that registry and credential events are only valid when the corresponding seal appears in the issuer's KEL at the claimed sequence number, enforced by `Tevery`.

---

**Regery (Registry Manager)**
- Axes: core | substantive | composite
- Regery is the code-layer registry context analogous to `Habery`: it assembles a `Reger` (TEL database), a `Tevery` (TEL event processor), and a `Parser` configured to handle both KERI and TEL event streams; it maintains a `regs` dict of `Registry` objects for all locally managed credential registries.

---

**Reger (Registry Database)**
- Axes: core | non-trivial | composite
- Reger is the TEL-specific LMDB database that assembles sub-tables for TEL events, registry state records, credential issuance/revocation state, and TSN (Transaction State Notice) escrows via the `Broker` class; it parallels `Baser` in structure but is scoped entirely to credential lifecycle data.

---

**Tevery (TEL Event Processor)**
- Axes: core | substantive | composite
- Tevery is the TEL-domain equivalent of `Kevery`: it validates incoming TEL events (`vcp`, `iss`, `rev`) against registry state, enforces the KEL-anchor requirement, and applies validated events to `Tever` state objects; it assembles escrow processing for out-of-order TEL events and for events awaiting KEL confirmation.

---

**Schemer (Credential Schema)**
- Axes: core | non-trivial | composite
- Schemer assembles a SAID-identified JSON Schema document with a `jsonschema`-backed validation wrapper and a Baser schema cache; it provides `verify(data)` which checks that an ACDC's attribute block conforms to the schema document identified by the credential's `s` field SAID.

---

**IPEX (Issuance and Presentation Exchange)**
- Axes: core | complex | composite
- IPEX is the six-step credential negotiation protocol carried over `exn` messages: apply → offer → agree → grant → admit (or spurn at any step); its invariant is that each step's `p` field must contain the SAID of the immediately preceding step in the negotiation chain, enforced by `IpexHandler.verify()`, and a `grant` message must attach the full ACDC and its TEL anchoring proof.

---

---

#### BC-7: Peer Messaging

---

**EXN (Exchange Message)**
- Axes: core | substantive | composite
- An exchange message assembles an `exn`-ilk `SerderKERI` body (route, sender AID, datetime, payload), attached `Siger` signatures, and optional CESR SAD-path attachments; it is routed by `Exchanger` to the handler registered for the message's `r` field route path, and its invariant is that the sender AID must be verifiable against a known KEL and the message timestamp must fall within the `ExchangeMessageTimeWindow` (300 seconds).

---

**Exchanger (EXN Router)**
- Axes: core | substantive | composite
- Exchanger assembles a route-to-handler registry dict, a partial-sig escrow for `exn` messages awaiting additional signatures, and a `Cues` Deck for handler responses; its `processEvent()` method validates sender AID, timestamp, and signatures before dispatching to the registered handler, and its invariant is that each route path has at most one registered handler.

---

**Counselor (Multisig Coordinator)**
- Axes: core | complex | composite
- Counselor assembles a partial-signature escrow (`hby.db.gpse`), a delegation `Anchorer`, a `WitnessInquisitor`, and a `WitnessReceiptor` into a single `DoDoer`; its `start()` method registers a group event for collection, and its `escrowDo()` loop advances events from partial-sig → fully-signed → witnessed → delegated, enforcing that a group event is submitted to witnesses only after all required co-signers have provided their signatures.

---

**Anchorer (Delegation Anchor Doer)**
- Axes: core | substantive | composite
- Anchorer assembles a `Poster` (for sending `exn` delegation notifications to the delegator), a `WitnessPublisher`, a `WitnessInquisitor`, and a delegation-partial-witness escrow; its `delegation()` method sends the delegatee's event to witnesses, and its `escrowDo()` loop advances only when the delegator's KEL is observed to contain the required anchor seal for the delegatee's event.

---

### 5.4 Absent Concepts

The following concepts are named in specifications or prior phases but have no physical representation in the keripy file graph.

| Concept | Type | Source | Notes |
|---|---|---|---|
| Dber ABC (Durable Event Store port) | absent (named but unbuilt) | Phase 2 / V02 | No `ABC` or `Protocol` class for storage interface. `LMDBer` is the sole concrete satisfier with no abstraction layer. |
| Signing Oracle port | absent (named but unbuilt) | Phase 2 / ED-1 | No ABC for signing algorithm dispatch. `pysodium` and `cryptography` imported directly in domain files. |
| Digest Oracle port | absent (named but unbuilt) | Phase 2 / ED-2 | No ABC for digest algorithm dispatch. `blake3` and `hashlib` imported directly in `Diger`. |
| Validator (as named role) | absent (assumed but unspecced) | KERI spec | Spec describes "validator" as a role. keripy embeds validation logic in `Kevery`; no named `Validator` class exists. |

---

*End of Phase 3 output. Sections 6–9 to be produced in subsequent phases.*

---

## Section 6 — Composite Decomposition Trees

### 6.1 Scope and Notation

This section provides a complete decomposition for all 36 composite concepts catalogued in Section 5.2. Trees and envelope specs are organized by bounded context (BC-1 through BC-7) in the same order as Section 5.

**Tree notation conventions:**
- Leaf nodes are `atomic`; every domain-owned leaf must have a Section 5 registry entry.
- `↪ §6.2 [Name]` — composite child; not recursed inline; see its own subsection.
- `[unlisted]` — child has no Section 5 registry entry; newly identified absence (see §6.4).
- `[ext: ED-N]` — belongs to External Domain N (see Section 4.1); not a domain concept.

**Convergence check:** All `[unlisted]` nodes are catalogued in §6.4 as candidate concepts for the next iteration pass.

---

### 6.2 Decomposition Trees

---

#### BC-1 — Event Processing

---

**Key Event**

```
Key Event  (core, substantive, composite)
  ├── Serder / SerderKERI  (core, substantive, composite)  ↪ §6.2 Serder
  ├── Siger [list]  (core, non-trivial, atomic)   → owns: indexed signature(s) binding each signing key to the event body
  ├── Prefixer  (core, substantive, atomic)        → owns: AID prefix identifying the controller whose key state this event updates
  └── Seqner  (core, trivial, atomic)              → owns: event position in the KEL as a CESR-typed sequence number
```

---

**Key Event Log (KEL)**

```
Key Event Log  (core, complex, composite)
  ├── Key Event  (core, substantive, composite)  ↪ §6.2 Key Event  [× N, ordered by Seqner]
  └── Baser (sub-tables: evts, fels, dtss, snkey)  (core, complex, composite)  ↪ §6.2 Baser
```

---

**KERL (Key Event Receipt Log)**

```
KERL  (core, substantive, composite)
  ├── Key Event Log  (core, complex, composite)    ↪ §6.2 Key Event Log
  ├── Receipt  (core, non-trivial, atomic)          → owns: witness countersignature attesting event authenticity
  ├── KAWA / Witness Quorum  (core, complex, atomic)  → owns: BFT quorum threshold computation (ample/simple) over receipt count
  └── TOAD  (core, non-trivial, atomic)             → owns: integer threshold of accountable duplicity governing receipt quorum
```

---

**Kever (Key State)**

```
Kever  (core, complex, composite)
  ├── Prefixer  (core, substantive, atomic)            → owns: AID prefix whose key state this object tracks
  ├── Verfer [list]  (core, non-trivial, atomic)       → owns: current public signing keys
  ├── Tholder (current)  (core, substantive, atomic)   → owns: current signing threshold (M-of-N or weighted)
  ├── Diger [list] (ndigers)  (core, non-trivial, atomic)  → owns: next-key digest commitments for pre-rotation
  ├── Tholder (next)  (core, substantive, atomic)      → owns: next signing threshold committed at this establishment event
  ├── Seqner  (core, trivial, atomic)                  → owns: current sequence number of this key state
  ├── TOAD  (core, non-trivial, atomic)                → owns: current witness quorum threshold value
  ├── Pre-rotation  (core, complex, atomic)            → owns: invariant enforcement: new rotation keys must satisfy prior ndigers
  ├── Baser  (core, complex, composite)               ↪ §6.2 Baser
  └── Dater  [unlisted]                               → owns: ISO datetime of first-seen event (hio Dater primitive)
```

---

**Kevery (Event Processing Facility)**

```
Kevery  (core, complex, composite)
  ├── Kever  (core, complex, composite)         ↪ §6.2 Kever  [factory target: one per AID]
  ├── Baser  (core, complex, composite)         ↪ §6.2 Baser
  ├── Escrow  (core, substantive, composite)    ↪ §6.2 Escrow
  ├── Exchanger (exc)  (core, substantive, composite)  ↪ §6.2 Exchanger
  ├── Tevery (tvy)  (core, substantive, composite)     ↪ §6.2 Tevery
  └── Deck (cues)  [ext: ED-5]                         → owns: hio FIFO queue for outbound event cues
```

---

**Escrow**

```
Escrow  (core, substantive, composite)
  ├── Baser (escrow sub-tables: ooes, pses, pwes, ldes, uwes, ures, vres, ksns, qnfs)
  │         (core, complex, composite)  ↪ §6.2 Baser
  ├── Broker  [unlisted]               → owns: TEL-side escrow sub-tables in Reger for state notices; db/escrowing.py
  └── processEscrow* methods  [unlisted]  → owns: nine named escrow evaluation loops with timeout logic; pure behavioral
```

---

**Inception Event (icp / dip)**

```
Inception Event  (core, substantive, composite)
  ├── Serder / SerderKERI  (core, substantive, composite)  ↪ §6.2 Serder
  ├── Siger [list]  (core, non-trivial, atomic)            → owns: controller signature(s) over inception body
  ├── Prefixer  (core, substantive, atomic)                → owns: AID prefix derived from event SAID or initial public key
  ├── Verfer [list]  (core, non-trivial, atomic)           → owns: initial signing public keys
  ├── Tholder  (core, substantive, atomic)                 → owns: initial signing threshold
  ├── Diger [list] (ndigers)  (core, non-trivial, atomic)  → owns: first pre-rotation key digest commitments
  ├── TOAD  (core, non-trivial, atomic)                    → owns: initial witness quorum threshold
  ├── Seqner  (core, trivial, atomic)                      → owns: sequence number 0 (always for inception)
  ├── Seal [list]  (core, non-trivial, atomic)             → owns: optional data anchors in the inception body
  └── Seal (delegator anchor, dip only)  (core, non-trivial, atomic)  → owns: SealEvent pointing to delegator's approving event
```

---

**Rotation Event (rot / drt)**

```
Rotation Event  (core, substantive, composite)
  ├── Serder / SerderKERI  (core, substantive, composite)  ↪ §6.2 Serder
  ├── Siger [list]  (core, non-trivial, atomic)            → owns: signatures from the new signing key set
  ├── Prefixer  (core, substantive, atomic)                → owns: AID prefix of the rotating identifier
  ├── Verfer [list]  (core, non-trivial, atomic)           → owns: new signing public keys replacing prior set
  ├── Pre-rotation  (core, complex, atomic)                → owns: proof that new keys hash to prior ndigers commitments
  ├── Tholder  (core, substantive, atomic)                 → owns: new signing threshold
  ├── Diger [list] (new ndigers)  (core, non-trivial, atomic)  → owns: next pre-rotation commitments
  ├── Seqner  (core, trivial, atomic)                      → owns: sequence number of this rotation event
  ├── Cuts / Adds  [unlisted]                              → owns: witness pool delta lists; present in event body, unnamed in §5
  └── Seal (delegator anchor, drt only)  (core, non-trivial, atomic)  → owns: SealEvent from delegator's KEL approving this rotation
```

---

**Delegation**

```
Delegation  (core, complex, composite)
  ├── Inception Event or Rotation Event  (core, substantive, composite)  ↪ §6.2 Inception Event / Rotation Event
  ├── Seal (delegator anchor)  (core, non-trivial, atomic)  → owns: cryptographic proof embedding delegatee event SAID in delegator's KEL
  ├── Anchorer  (core, substantive, composite)              ↪ §6.2 Anchorer
  └── Kever  (core, complex, composite)                     ↪ §6.2 Kever  [delegator key state, verified before anchor acceptance]
```

---

#### BC-2 — Key Management

---

**Hab (Habitat)**

```
Hab  (core, complex, composite)
  ├── Kever  (core, complex, composite)          ↪ §6.2 Kever  [own AID's verified key state]
  ├── Habery  (core, substantive, composite)     ↪ §6.2 Habery  [shared Baser + Keeper + Manager]
  ├── Kevery  (core, complex, composite)         ↪ §6.2 Kevery  [dedicated local event processor]
  ├── AID / Prefixer  (core, substantive, atomic)  → owns: this Hab's self-certifying identifier
  └── Parser  [unlisted]                            → owns: local message parser feeding Kevery; core/parsing.py
```

---

**Habery (Habitat Registry)**

```
Habery  (core, substantive, composite)
  ├── Keeper  (core, substantive, composite)     ↪ §6.2 Keeper
  ├── Baser  (core, complex, composite)          ↪ §6.2 Baser
  ├── Manager  (core, complex, composite)        ↪ §6.2 Manager
  ├── Kevery  (core, complex, composite)         ↪ §6.2 Kevery  [shared event processor for all local Habs]
  ├── Router / Revery  [unlisted]                → owns: reply-message routing; core/routing.py Router and Revery
  └── Configer  [unlisted]                       → owns: HJSON configuration file reader; app/configing.py
```

---

**GroupHab (Multi-sig Habitat)**

```
GroupHab  (core, complex, composite)
  ├── Hab [list]  (core, complex, composite)     ↪ §6.2 Hab  [participant Habs: local + referenced remote]
  ├── Tholder (group)  (core, substantive, atomic)  → owns: multi-party signing threshold for the group AID
  ├── AID / Prefixer (group)  (core, substantive, atomic)  → owns: group AID prefix from group inception event
  └── Partial-sig escrow (gpse)  [unlisted]         → owns: Baser.gpse sub-table for co-signer signature collection
```

---

**Manager (Key Manager)**

```
Manager  (core, complex, composite)
  ├── Keeper  (core, substantive, composite)  ↪ §6.2 Keeper
  ├── Salter  (core, substantive, atomic)     → owns: deterministic key derivation from root salt via pidx+ridx+kidx triplet
  ├── Encrypter  [unlisted]                   → owns: AES-GCM encryption of private keys before Keeper storage; core/coring.py
  └── Decrypter  [unlisted]                   → owns: AES-GCM decryption of private keys transiently during signing; core/coring.py
```

---

**Keeper (Keystore)**

```
Keeper  (core, substantive, composite)
  ├── LMDBer  (peripheral, substantive, composite)     ↪ §6.2 LMDBer
  ├── PubLot / PreSit  (peripheral, non-trivial, composite)  ↪ §6.2 PubLot/PreSit
  ├── pris sub-table  [unlisted]              → owns: AES-encrypted private key storage keyed by public key; CryptSignerSuber
  ├── pubs sub-table  [unlisted]              → owns: ordered public-key-set index by prefix+ridx; Komer
  └── gbls sub-table  [unlisted]              → owns: global keystore parameters (aeid, pidx, algo, salt, tier); Suber
```

---

**PubLot / PreSit**

```
PubLot / PreSit  (peripheral, non-trivial, composite)
  ├── old PubLot  [unlisted]  → owns: previous public key set with rotation index (ridx) and key index (kidx); dataclass
  ├── new PubLot  [unlisted]  → owns: current public key set with ridx and kidx; dataclass
  └── nxt PubLot  [unlisted]  → owns: next (pre-rotated) public key set with ridx and kidx; dataclass
```

*Note: All three children are unnamed dataclass instances within `keeping.py`. No child has an independent Section 5 registry entry. All three are `[unlisted]`; see §6.4.*

---

#### BC-3 — CESR Encoding

---

**Serder (Event Message Container)**

```
Serder  (core, substantive, composite)
  ├── SAID  (core, substantive, atomic)               → owns: content-addressable identifier computed by placeholder-digest-embed cycle
  ├── Version String / Versionage  (peripheral, non-trivial, atomic)  → owns: wire-format version string (protocol, version, kind, size)
  ├── Serialization Format Codec  [ext: ED-6]         → owns: JSON / CBOR / MsgPack encode-decode algorithm; external domain
  └── SAD dict  [unlisted]                            → owns: deserialized event field map (Python dict); in-memory representation
```

---

#### BC-4 — Persistence

---

**Baser (KERI Event Database)**

```
Baser  (core, complex, composite)
  ├── LMDBer  (peripheral, substantive, composite)     ↪ §6.2 LMDBer
  ├── KeyStateRecord  (core, non-trivial, atomic)      → owns: persisted Kever snapshot for cold-start reconstruction
  ├── OobiRecord  (peripheral, non-trivial, atomic)    → owns: OOBI resolution state per URL+AID pair
  ├── EndpointRecord  (peripheral, non-trivial, atomic)  → owns: endpoint role/scheme/location triple for an AID
  ├── Schemer (schema cache)  (core, non-trivial, composite)  ↪ §6.2 Schemer
  └── 50+ named sub-tables  [unlisted]                → owns: evts, fels, rcts, wigs, ldes, pses, pwes, etc. (Suber/Komer/IoSetSuber instances)
```

---

**LMDBer (LMDB Base Adapter)**

```
LMDBer  (peripheral, substantive, composite)
  ├── lmdb.Environment  [ext: ED-3]  → owns: LMDB database environment, file mapping, and transaction management
  └── Filer  [ext: ED-5]             → owns: directory and file lifecycle management; hio.base.filing.Filer
```

---

#### BC-5 — Infrastructure Services

---

**Witness**

```
Witness  (core, complex, composite)
  ├── WitnessReceiptor  (core, non-trivial, composite)   ↪ §6.2 WitnessReceiptor
  ├── WitnessPublisher  (core, non-trivial, composite)   ↪ §6.2 WitnessPublisher
  ├── WitnessInquisitor  (core, non-trivial, composite)  ↪ §6.2 WitnessInquisitor
  └── Kevery  (core, complex, composite)                 ↪ §6.2 Kevery  [own event validator: witness verifies before receipting]
```

*Physical note: No named `Witness` class exists. The concept is assembled by `WitnessStart` (`app/indirecting.py:146`) which composes these Doers via the hio DoDoer pattern.*

---

**Watcher**

```
Watcher  (core, substantive, composite)
  ├── Kevery  (core, complex, composite)                ↪ §6.2 Kevery  [validator-mode processor for watched AIDs]
  ├── WitnessInquisitor  (core, non-trivial, composite) ↪ §6.2 WitnessInquisitor  [query interface polling witnesses]
  └── Adjudicator  [unlisted]                           → owns: key state adjudication logic comparing multi-watcher reports; app/watching.py
```

*Physical note: No named `Watcher` class. The concept is assembled from `Adjudicator` + `WitnessInquisitor` + `Kevery` in `app/watching.py`.*

---

**OOBI (Out-of-Band Introduction)**

```
OOBI  (core, substantive, composite)
  ├── OobiRecord  (peripheral, non-trivial, atomic)    → owns: persisted OOBI state (URL, AID, role, resolved flag, datetime)
  ├── EndpointRecord  (peripheral, non-trivial, atomic)  → owns: resolved endpoint location stored on successful resolution
  ├── Kevery  (core, complex, composite)               ↪ §6.2 Kevery  [validates key event stream from OOBI URL response]
  ├── Baser  (core, complex, composite)                ↪ §6.2 Baser  [stores OobiRecord and EndpointRecord]
  └── OobiResolver  [unlisted]                         → owns: HTTP fetch + parse pipeline for OOBI resolution; app/oobiing.py
```

---

**Mailbox**

```
Mailbox  (peripheral, non-trivial, composite)
  ├── Baser (mbx sub-table)  (core, complex, composite)  ↪ §6.2 Baser
  └── Topic-keyed delivery index  [unlisted]              → owns: per-AID/per-topic message cursor sub-table (IoSetSuber); not a named §5 concept
```

---

**WitnessReceiptor**

```
WitnessReceiptor  (core, non-trivial, composite)
  ├── Habery  (core, substantive, composite)  ↪ §6.2 Habery  [AID + witness list lookup]
  ├── Deck (msgs)  [ext: ED-5]                → owns: incoming event queue (pre+sn pairs to receipt)
  └── Deck (cues)  [ext: ED-5]                → owns: outbound confirmed-receipt cues
```

---

**WitnessPublisher**

```
WitnessPublisher  (core, non-trivial, composite)
  ├── Habery  (core, substantive, composite)  ↪ §6.2 Habery
  ├── Deck (msgs)  [ext: ED-5]                → owns: incoming publish queue (pre + serialized message)
  └── Deck (cues)  [ext: ED-5]                → owns: outbound send-confirmation cues
```

---

**WitnessInquisitor**

```
WitnessInquisitor  (core, non-trivial, composite)
  ├── Habery  (core, substantive, composite)  ↪ §6.2 Habery  [endpoint role record lookup]
  └── Deck (msgs)  [ext: ED-5]                → owns: query message buffer (pre + target + route + q params)
```

---

#### BC-6 — Verifiable Credentials (ACDC)

---

**ACDC (Authentic Chained Data Container)**

```
ACDC  (core, complex, composite)
  ├── Serder / SerderACDC  (core, substantive, composite)  ↪ §6.2 Serder
  ├── SAID  (core, substantive, atomic)              → owns: content-addressable ACDC identifier embedded in `d` field
  ├── Seal  (core, non-trivial, atomic)              → owns: SealEvent anchoring ACDC issuance to issuer AID KEL at specific sn
  ├── Schemer  (core, non-trivial, composite)        ↪ §6.2 Schemer  [validates attribute block against schema SAID]
  ├── Kever  (core, complex, composite)              ↪ §6.2 Kever  [issuer AID key state at anchoring sequence number]
  └── Edge list  [unlisted]                          → owns: `e` field credential chain edges linking to prior credentials
```

---

**VDR / TEL (Transaction Event Log)**

```
VDR / TEL  (core, complex, composite)
  ├── Key Event (TEL variant: vcp, iss, rev)  (core, substantive, composite)  ↪ §6.2 Key Event
  ├── Tevery  (core, substantive, composite)   ↪ §6.2 Tevery  [TEL event processor parallel to Kevery]
  ├── Seal  (core, non-trivial, atomic)        → owns: anchors each TEL event to issuer's KEL at a specific sn
  └── Reger  (core, non-trivial, composite)    ↪ §6.2 Reger  [TEL event storage database]
```

---

**Regery (Registry Manager)**

```
Regery  (core, substantive, composite)
  ├── Reger  (core, non-trivial, composite)     ↪ §6.2 Reger
  ├── Tevery  (core, substantive, composite)    ↪ §6.2 Tevery
  ├── Habery  (core, substantive, composite)    ↪ §6.2 Habery  [controller context: Baser + Hab]
  └── Registry  [unlisted]                      → owns: per-registry record linking registry key, issuer AID, TEL state; credentialing.py
```

---

**Reger (Registry Database)**

```
Reger  (core, non-trivial, composite)
  ├── LMDBer  (peripheral, substantive, composite)  ↪ §6.2 LMDBer
  └── TEL sub-tables  [unlisted]                    → owns: tels, tewe, tede, ares, crds, ancs, tpwe, tpse and related sub-tables; vdr/viring.py
```

---

**Tevery (TEL Event Processor)**

```
Tevery  (core, substantive, composite)
  ├── Reger  (core, non-trivial, composite)   ↪ §6.2 Reger
  ├── Baser  (core, complex, composite)       ↪ §6.2 Baser  [issuer AID key state lookup via db.kevers]
  ├── Kever  (core, complex, composite)       ↪ §6.2 Kever  [issuer key state for TEL anchor verification]
  └── Tever  [unlisted]                       → owns: in-memory TEL state object parallel to Kever; vdr/eventing.py:Tever
```

---

**Schemer (Credential Schema)**

```
Schemer  (core, non-trivial, composite)
  ├── SAID  (core, substantive, atomic)           → owns: schema's content-addressable identifier (must match schema body digest)
  ├── Baser (schema cache)  (core, complex, composite)  ↪ §6.2 Baser
  └── JSON Schema Validator  [ext: ED-7]          → owns: jsonschema RFC draft validation algorithm; external domain
```

---

**IPEX (Issuance and Presentation Exchange)**

```
IPEX  (core, complex, composite)
  ├── EXN  (core, substantive, composite)          ↪ §6.2 EXN  [each step: apply/offer/agree/grant/admit/spurn is an exn message]
  ├── SAID  (core, substantive, atomic)            → owns: prior-step SAID in `p` field that chains the six-step protocol
  ├── Serder / SerderACDC  (core, substantive, composite)  ↪ §6.2 Serder  [grant message carries full ACDC body]
  └── IpexHandler  [unlisted]                      → owns: route-registered handler dispatching each IPEX step; vc/protocoling.py
```

---

#### BC-7 — Peer Messaging

---

**EXN (Exchange Message)**

```
EXN  (core, substantive, composite)
  ├── Serder / SerderKERI  (core, substantive, composite)  ↪ §6.2 Serder  [exn-ilk body: route, sender AID, datetime, payload]
  ├── Siger [list]  (core, non-trivial, atomic)    → owns: transferable controller signatures over exn body
  ├── Cigar [list]  (core, non-trivial, atomic)    → owns: non-transferable signatures where applicable
  └── Exchanger  (core, substantive, composite)    ↪ §6.2 Exchanger  [routes EXN to registered handler by `r` field]
```

---

**Exchanger (EXN Router)**

```
Exchanger  (core, substantive, composite)
  ├── Kever  (core, complex, composite)       ↪ §6.2 Kever  [sender AID key state verification]
  ├── Route handler registry  [unlisted]      → owns: dict mapping route path strings to IHandler instances; peer/exchanging.py
  ├── Partial-sig escrow (pses)  [unlisted]   → owns: Baser sub-table for partially-signed exn messages awaiting more signatures
  └── Deck (cues)  [ext: ED-5]                → owns: outbound handler-response cue queue
```

---

**Counselor (Multisig Coordinator)**

```
Counselor  (core, complex, composite)
  ├── Anchorer  (core, substantive, composite)         ↪ §6.2 Anchorer
  ├── WitnessInquisitor  (core, non-trivial, composite)  ↪ §6.2 WitnessInquisitor
  ├── Receiptor  [unlisted]                             → owns: sends events+receipts to witnesses; agenting.Receiptor
  ├── GroupHab  (core, complex, composite)              ↪ §6.2 GroupHab  [multi-sig controller context]
  └── Partial-sig escrow (gpse)  [unlisted]             → owns: Baser.gpse sub-table for co-signer signature collection
```

---

**Anchorer (Delegation Anchor Doer)**

```
Anchorer  (core, substantive, composite)
  ├── Poster  [unlisted]                               → owns: forwarding.Poster sends exn delegation notification to delegator
  ├── WitnessInquisitor  (core, non-trivial, composite)  ↪ §6.2 WitnessInquisitor
  ├── Receiptor  [unlisted]                            → owns: agenting.Receiptor collects witness receipts for delegatee event
  ├── WitnessPublisher  (core, non-trivial, composite) ↪ §6.2 WitnessPublisher  [publishes delegatee event to witnesses]
  └── Delegation partial-witness escrow (dpwe)  [unlisted]  → owns: Baser.dpwe sub-table; event waits here until delegator anchor confirmed
```

---

### 6.3 Composite Envelope Specs

---

#### BC-1 — Event Processing

---

**Key Event**
- **Assembled From:** SerderKERI, Siger list, Prefixer, Seqner
- **Assembly Rationale:** A key event is the atomic unit of KEL change. The signed body (SerderKERI) carries the protocol meaning; the Siger list provides the cryptographic authorization; the Prefixer identifies the controller; the Seqner positions the event in the immutable sequence. No single component constitutes a key event alone.
- **Invariants at Envelope Level:** The Siger list must satisfy the current signing threshold (Tholder) of the AID. The Seqner must equal the next expected sequence number. The SerderKERI's `p` field must match the digest of the prior event. The Prefixer must match the event body's `i` field.
- **Does NOT own:** Key state interpretation (Kever), signature verification logic (Verfer.verify), digest computation (Diger), storage (Baser). These belong to children or to BC-1 Kever/BC-4 Baser.

---

**Key Event Log (KEL)**
- **Assembled From:** Key Event (× N, ordered), Baser (storage sub-tables)
- **Assembly Rationale:** The KEL is the container that gives Key Events their ordered, backward-chained meaning. A single Key Event has no sequential context; the KEL provides it. Baser provides the durability guarantee. Together they constitute the authoritative, tamper-evident history of an AID's key state.
- **Invariants at Envelope Level:** Events are append-only. Each event at position `n` must include the digest of the event at position `n-1`. The first-seen ordinal (fn) for each event is immutable once assigned. No event may be retracted.
- **Does NOT own:** Witness receipt tracking (KERL), key state computation (Kever), storage engine internals (LMDBer). These belong to KERL and Baser respectively.

---

**KERL (Key Event Receipt Log)**
- **Assembled From:** Key Event Log, Receipt list, KAWA / Witness Quorum, TOAD
- **Assembly Rationale:** The KERL extends the KEL with the witness promulgation layer. In indirect mode, a key event is not considered published until the receipt quorum is met. The KAWA quorum logic and TOAD value determine when the event transitions from "pending" to "promulgated." The Receipt list provides the cryptographic evidence.
- **Invariants at Envelope Level:** A key event transitions to promulgated only when the number of valid receipts ≥ TOAD. TOAD must be ≥ the value computed by `ample(n, f)` for the current witness pool size. Receipts must be from designated witnesses; receipts from non-witnesses are not counted.
- **Does NOT own:** Witness identity management (which AIDs are witnesses is recorded in Kever.wits, not KERL). Receipt signature verification (Verfer.verify). KEL event validation (Kevery).

---

**Kever (Key State)**
- **Assembled From:** Prefixer, Verfer list, Tholder (current), Diger list (ndigers), Tholder (next), Seqner, TOAD, Pre-rotation, Baser, Dater
- **Assembly Rationale:** Kever is the domain's authoritative materialization of "key state" as defined in the KERI spec. It holds the complete, verified, current signing configuration for one AID. Every field is needed to answer the question "is this event valid for this AID right now?" without re-reading the KEL.
- **Invariants at Envelope Level:** Kever is only mutated by a fully verified event through `Kever.update()`. Its fields are always internally consistent (Verfer list count matches Tholder denomination; ndigers count matches nTholder denomination). A Kever is always reachable by its Prefixer's qb64 from `db.kevers`.
- **Does NOT own:** Event parsing (Parser), validation pipeline (Kevery), persistence format (Baser sub-tables). Kever is the result of applying those components; it does not own them.

---

**Kevery (Event Processing Facility)**
- **Assembled From:** Kever (factory target), Baser, Escrow, Exchanger, Tevery, Deck (cues)
- **Assembly Rationale:** Kevery orchestrates the complete event acceptance pipeline: parse → validate → apply → escrow (if incomplete). It is the factory that creates and updates Kever instances. Baser provides durable state access. Escrow handles deferred events. Exchanger and Tevery handle non-KEL message types routed through the same parser stream.
- **Invariants at Envelope Level:** No non-idempotent database write may occur for an event that fails validation. Each escrow bucket has a named timeout. The cues Deck is the only side-channel for outbound work requests; no direct external calls from within Kevery.
- **Does NOT own:** Serialization format (Parser/Serder own that). Key generation (Manager). Network I/O (Protocol Message Channel port). Kever owns key state logic; Kevery owns the orchestration of that logic.

---

**Escrow**
- **Assembled From:** Baser (nine escrow sub-tables), Broker (TEL state notice escrow), processEscrow* methods
- **Assembly Rationale:** Escrow is a deferred-application holding system. Events and receipts that cannot be applied because prerequisite data is missing are stored in named buckets until re-evaluation. Each bucket corresponds to a distinct prerequisite failure mode (out-of-order, partially-signed, partial-witness, likely-duplicitous, unverified receipt (two kinds), unverified transferable receipt, key-state-notice, query-not-found).
- **Invariants at Envelope Level:** Each escrow bucket has a named timeout constant. Events in escrow are never applied non-idempotently. Re-evaluation is triggered by new incoming data (not by polling). An event that times out is discarded, not re-queued.
- **Does NOT own:** Storage engine (Baser/LMDBer own that). Validation logic (Kever owns that). The decision of which bucket an event lands in belongs to Kevery's dispatch logic.

---

**Inception Event (icp / dip)**
- **Assembled From:** SerderKERI, Siger list, Prefixer, Verfer list, Tholder, Diger list (ndigers), TOAD, Seqner, Seal list, Seal (delegator anchor, dip only)
- **Assembly Rationale:** The inception event is the unique, unrepeatable act that creates an AID. All components must be co-present: the signed body establishes what the AID is; the Verfer list establishes who can control it now; the Diger list establishes who can rotate it next; the TOAD establishes the witness trust model; the Prefixer ties the identifier itself to the cryptographic material. Omitting any component leaves the AID under-specified.
- **Invariants at Envelope Level:** Seqner must be 0. The Prefixer must be derivable from either the event SAID (self-addressing derivation) or the first public key (basic derivation). For `dip`, the delegator anchor Seal must reference an event in the delegator's KEL that includes the delegatee's inception event SAID. No second inception event for the same AID is ever valid.
- **Does NOT own:** Prefix derivation algorithm (Prefixer.verify). Signature threshold semantics (Tholder). The decision to accept the event (Kever.__init__). Storage (Baser).

---

**Rotation Event (rot / drt)**
- **Assembled From:** SerderKERI, Siger list, Prefixer, Verfer list, Pre-rotation, Tholder, Diger list (new ndigers), Seqner, Cuts/Adds, Seal (delegator anchor, drt only)
- **Assembly Rationale:** A rotation event transfers control by committing a new signing key set while satisfying the pre-rotation proof from the prior establishment event. Each component contributes a distinct invariant: Pre-rotation verifies the commitment was honored; Verfer list installs the new keys; new ndigers sets the next commitment; Cuts/Adds updates the witness pool; drt-only Seal binds delegator approval.
- **Invariants at Envelope Level:** The new Verfer keys must hash (under the declared algorithm) to match one of the prior ndigers commitments. Seqner must equal prior Kever sn + 1 (or higher for gap detection purposes). Cuts/Adds must not result in duplicate witnesses or witnesses appearing in both lists.
- **Does NOT own:** Pre-rotation mathematical proof (Pre-rotation owns that). Witness pool state after rotation (Kever.wits owns that). Validation and application (Kevery/Kever own that).

---

**Delegation**
- **Assembled From:** Inception Event or Rotation Event (delegatee), Seal (delegator anchor), Anchorer, Kever (delegator)
- **Assembly Rationale:** Delegation is not a single event but a synchronized two-KEL operation. The delegatee produces a `dip`/`drt` event; the delegator must include a Seal anchoring that event's SAID in a concurrent event. The Anchorer Doer orchestrates the synchronization: it sends the delegatee event to witnesses and monitors the delegator's KEL until the anchor appears. Kever provides the delegator key state required to validate the anchor.
- **Invariants at Envelope Level:** A `dip`/`drt` event is not applied to the delegatee's Kever until the delegator's KEL contains a valid SealEvent for it. The delegator seal must reference the exact event SAID (not just a sequence number). Delegation is not recursive beyond the depth the delegator's own establishment event permits.
- **Does NOT own:** The delegatee's key derivation (Manager/Salter own that). The delegator's event construction (delegator's own Hab owns that). Network transport to delegator (forwarding.Poster owns that).

---

#### BC-2 — Key Management

---

**Hab (Habitat)**
- **Assembled From:** Kever (own AID key state), Habery (shared Baser + Keeper + Manager), Kevery (local event processor), AID/Prefixer, Parser
- **Assembly Rationale:** Hab is the controller's operational context for one locally managed AID. It bundles the AID's current key state (Kever), the event-processing pipeline (Kevery + Parser), and access to shared infrastructure (Habery: database, key manager, keystore). Without Hab, these components would need to be manually assembled and kept consistent for every operation. Hab provides the convenience boundary.
- **Invariants at Envelope Level:** Hab's `pre` field is immutable after inception. All event construction methods (`makeOwnEvent`, `sign`) must route through the Manager within Habery — never directly to raw private keys. `Hab.inited` must be True before any event construction.
- **Does NOT own:** The shared Baser database (Habery owns it). Private key material (Manager within Habery owns it). Network I/O.

---

**Habery (Habitat Registry)**
- **Assembled From:** Keeper, Baser, Manager, Kevery (shared), Router/Revery, Configer
- **Assembly Rationale:** Habery is the shared environment owner. Multiple Hab instances for different AIDs must share the same encrypted keystore (Keeper) and event database (Baser) to enable multi-identifier management with a single passcode. Manager provides the signing authority across all Habs. Kevery provides the shared event validation context. Router/Revery handle reply-message routing. Configer loads operator settings.
- **Invariants at Envelope Level:** All Habs within one Habery share exactly one Keeper and one Baser. The Manager is initialized with a single AEID-derived decryption key. Habery must be opened (`.opened == True`) before any Hab is created. The `habs` dict keyed by prefix is the authoritative Hab registry.
- **Does NOT own:** Individual AID key state (each Hab's Kever owns that). Event construction for a specific AID (each Hab owns that). The actual LMDB storage engine internals (LMDBer owns that).

---

**GroupHab (Multi-sig Habitat)**
- **Assembled From:** Hab list (participants: local + remote), Tholder (group), AID/Prefixer (group), Partial-sig escrow (gpse)
- **Assembly Rationale:** GroupHab extends Hab to represent an AID whose control is split across multiple parties. No single participant's key set satisfies the signing threshold alone. GroupHab assembles all participant Hab references to enable partial-signature collection and threshold evaluation before event submission.
- **Invariants at Envelope Level:** The group AID's Tholder denomination must match the number of participating signers required. An event is only submitted to witnesses after collecting enough signatures to satisfy the threshold. Each participant Hab is either local (key material accessible) or referenced (coordination only).
- **Does NOT own:** Individual participant key derivation (each participant's Manager owns that). Receipt collection (Counselor/Receiptor own that). Delegation coordination (Anchorer owns that).

---

**Manager (Key Manager)**
- **Assembled From:** Keeper, Salter, Encrypter, Decrypter
- **Assembly Rationale:** Manager is the single point of authority over private key material lifecycle. Salter generates key material from seeds. Encrypter/Decrypter protect private keys at rest and in transit within the process. Keeper persists the encrypted results. Together they form a closed loop: generate → encrypt → store → decrypt transiently → sign → zero.
- **Invariants at Envelope Level:** Private key bytes are never persisted in plaintext. Private keys are zeroed from memory after use. Decryption requires the AEID-derived seed, which is loaded once per process start. All key derivation is deterministic given the same salt + index triplet.
- **Does NOT own:** The encrypted storage format details (Keeper owns that). The signing algorithm (Verfer.verify and pysodium/cryptography own that). The public key encoding (Verfer/Matter own that).

---

**Keeper (Keystore)**
- **Assembled From:** LMDBer, PubLot/PreSit, pris sub-table, pubs sub-table, gbls sub-table
- **Assembly Rationale:** Keeper is the durable encrypted storage for all private key material associated with locally controlled AIDs. LMDBer provides the storage engine. PubLot/PreSit records track the rotation state (old/new/nxt key sets). Separate sub-tables separate concerns: pris for encrypted private keys, pubs for public key set ordering, gbls for root parameters.
- **Invariants at Envelope Level:** Every entry in pris is encrypted under the AEID-derived key before storage. The pubs and sits sub-tables are consistent with each other: any public key in pubs has a corresponding rotation index entry in sits. Keeper remains closed (not opened) until explicitly opened by Habery or Manager.
- **Does NOT own:** Encryption algorithm (Manager's Encrypter/Decrypter own that). Key derivation from salt (Salter owns that). The event database (Baser owns that).

---

**PubLot / PreSit**
- **Assembled From:** old PubLot, new PubLot, nxt PubLot (each a dataclass with pubs, ridx, kidx, dt fields)
- **Assembly Rationale:** PreSit captures the three-phase key rotation state for a single AID: the previously active key set (old), the currently active set (new), and the pre-committed next set (nxt). This three-way record is the minimal state needed to safely execute a rotation: old provides rollback reference, new provides current signing keys, nxt provides the next pre-rotation.
- **Invariants at Envelope Level:** The ridx of nxt is always exactly 1 greater than the ridx of new. The kidx values within each PubLot are contiguous. The dt field records when each phase was activated. After a rotation, old ← new, new ← nxt, and nxt is newly derived.
- **Does NOT own:** The actual private keys (pris sub-table in Keeper owns those). The public key encoding (Verfer/Matter own that).

---

#### BC-3 — CESR Encoding

---

**Serder (Event Message Container)**
- **Assembled From:** SAID, Version String / Versionage, Serialization Format Codec (external), SAD dict
- **Assembly Rationale:** Serder is the domain's gateway between raw bytes and a typed, self-describing protocol message. SAID provides the content-addressable identity. Version String enables versioned parsing. The codec handles multi-format wire encoding. The SAD dict provides the in-memory field map for domain logic to inspect. None of these components is meaningful in isolation for protocol processing.
- **Invariants at Envelope Level:** `serder.said` must always equal the Blake3-256 digest of the event body with the `d` field replaced by the dummy filler string. `serder.raw` must round-trip through the codec to reproduce `serder.sad` exactly. The version string byte count must equal `len(serder.raw)`.
- **Does NOT own:** Event field semantics (each event type's SerderKERI or SerderACDC subclass owns field-level logic). CESR attachment parsing (Parser/Counter own that). Signature verification (Siger/Verfer own that).

---

#### BC-4 — Persistence

---

**Baser (KERI Event Database)**
- **Assembled From:** LMDBer, KeyStateRecord, OobiRecord, EndpointRecord, Schemer (schema cache), 50+ named sub-tables
- **Assembly Rationale:** Baser is the domain's durable state repository. Every aspect of KERI state that must survive process restart lives here: the KEL (evts, fels, dtss), witness receipts (rcts, wigs), escrow buckets (pses, pwes, ldes, ooes, ures, uwes, vres), endpoint records, OOBI records, key state snapshots (states), and schema cache. The domain topology (what sub-tables exist and what they mean) is owned here.
- **Invariants at Envelope Level:** All sub-table keys follow the `dgKey(pre, dig)` or `snKey(pre, sn)` composite-key convention. The `kevers` dict property provides a read-through cache of KeyStateRecords. Sub-tables are opened atomically when Baser is opened. The `prefixes` OrderedSet is the authoritative set of locally owned AID prefixes.
- **Does NOT own:** Storage engine internals (LMDBer owns LMDB transactions and environment). Key state computation (Kever owns that). Schema validation logic (Schemer owns that).

---

**LMDBer (LMDB Base Adapter)**
- **Assembled From:** lmdb.Environment (external), Filer (external)
- **Assembly Rationale:** LMDBer wraps the LMDB storage engine behind a domain-named class hierarchy, providing sub-database management helpers (`getVal`, `putVal`, `delVal`, `getIoVals`, etc.) in domain-compatible terms. Filer provides directory lifecycle (create on open, delete on close for temp). Together they constitute the sole concrete satisfier of the Durable Event Store port.
- **Invariants at Envelope Level:** The LMDB environment is opened with `writemap=True` and `dupsort` settings appropriate to each sub-database type. LMDBer is the only class that calls `lmdb` APIs directly. All Baser, Keeper, and Reger sub-table operations route through LMDBer helpers.
- **Does NOT own:** Domain key schema (Baser/Keeper/Reger own that). CESR serialization of stored values (Serder/Matter own that). The `Dber` ABC port abstraction (V02 violation: absent).

---

#### BC-5 — Infrastructure Services

---

**Witness**
- **Assembled From:** WitnessReceiptor, WitnessPublisher, WitnessInquisitor, Kevery (own validator)
- **Assembly Rationale:** A Witness node assembles four roles into one operational unit: receiving events and sending them to witnesses for receipting (WitnessReceiptor), publishing completed receipts to all witnesses (WitnessPublisher), querying peers for missing receipts (WitnessInquisitor), and independently validating all incoming events before countersigning (Kevery). A Witness that receipts without verifying would violate the protocol's security model.
- **Invariants at Envelope Level:** A Witness must not issue a receipt for an event that its own Kevery has not successfully validated. A Witness's KEL for any AID it witnesses must be kept current via WitnessInquisitor queries. Receipt quorum is evaluated externally (by the controller's Kevery); the Witness's role is to produce valid receipts, not to enforce quorum.
- **Does NOT own:** Quorum evaluation (controller's Kevery/KAWA owns that). Witness pool selection (controller's inception/rotation event owns that). Network transport (Protocol Message Channel port owns that).

---

**Watcher**
- **Assembled From:** Kevery (validator mode), WitnessInquisitor (query interface), Adjudicator (key state adjudication)
- **Assembly Rationale:** A Watcher serves a validator's need to monitor foreign AIDs without being declared in their KELs. Kevery validates incoming key event streams. WitnessInquisitor fetches updates from witnesses of watched AIDs. Adjudicator compares key state reports across multiple watchers to detect inconsistency and duplicity. The combination enforces the first-seen rule and raises alarms on divergence.
- **Invariants at Envelope Level:** Once a Watcher observes event `n` for an AID, any conflicting event at the same sequence number is classified as duplicity and stored as evidence. The Adjudicator requires a quorum of consistent watcher reports before upgrading key state. Watcher identity is never published in any AID's KEL.
- **Does NOT own:** First-seen consensus among witnesses (KAWA owns that). Validator's trust policy (caller of Adjudicator owns that). Network transport.

---

**OOBI (Out-of-Band Introduction)**
- **Assembled From:** OobiRecord, EndpointRecord, Kevery (validator), Baser (storage), OobiResolver (fetch pipeline)
- **Assembly Rationale:** An OOBI is the domain's bootstrap mechanism for AID discovery outside the core protocol stream. A URL and AID pair is useless without a pipeline to resolve them: OobiResolver fetches the URL, Kevery validates the returned key event stream, Baser persists the results, and OobiRecord/EndpointRecord capture the resolved state. Each component handles one phase of the resolution lifecycle.
- **Invariants at Envelope Level:** An OOBI resolves successfully only when the response contains a valid, verifiable key event stream for the stated AID. A resolved OobiRecord transitions from `failed` to `resolved` status atomically. The EndpointRecord written on resolution is keyed by AID + role. Stale OobiRecords can be re-resolved by re-triggering the resolution pipeline.
- **Does NOT own:** HTTP transport (Protocol Message Channel port owns that). The AID's KEL content (Kevery/Kever own that). Endpoint routing logic (Infrastructure Services owns that).

---

**Mailbox**
- **Assembled From:** Baser (mbx sub-table), Topic-keyed delivery index
- **Assembly Rationale:** Mailbox decouples message producers (witnesses sending receipts, multi-sig participants sending partial signatures) from potentially-offline consumers (controllers). The mbx sub-table in Baser provides durable storage. The topic-keyed delivery index allows consumers to poll from their last-read cursor without reprocessing old messages.
- **Invariants at Envelope Level:** Messages are appended to the mailbox and never deleted by the producer. Consumer advancement is tracked per-AID/per-topic. Mailbox is write-once by the infrastructure; consumer delivery tracking is consumer-side.
- **Does NOT own:** Message format or content (each message type owns its schema). Message validation (Kevery owns that for KEL messages). Transport to consumer (Protocol Message Channel port owns that).

---

**WitnessReceiptor**
- **Assembled From:** Habery (AID + witness list lookup), Deck (msgs), Deck (cues)
- **Assembly Rationale:** WitnessReceiptor encapsulates the receipt-collection cycle: it reads the AID and witness list from Habery, sends the target event to each witness, collects receipts, propagates them to all other witnesses, and signals completion via the cues Deck. Habery provides all the context; the Decks provide the async message interface.
- **Invariants at Envelope Level:** WitnessReceiptor terminates when all current witnesses have been sent the complete receipt set. It processes one event at a time from the msgs Deck. It does not validate receipts — only collects and redistributes them.
- **Does NOT own:** Receipt content verification (Kevery/Kever own that). Witness AID selection (Kever.wits owns that). Network transport.

---

**WitnessPublisher**
- **Assembled From:** Habery, Deck (msgs), Deck (cues)
- **Assembly Rationale:** WitnessPublisher sends arbitrary KERI messages (events, receipts) to the full witness pool. It complements WitnessReceiptor by handling the publish-without-receipt path. Used when a controller needs to push an already-receipted event to witnesses that may have missed it.
- **Invariants at Envelope Level:** WitnessPublisher sends to all witnesses in Kever.wits, not a subset. It exits Done when all sends are completed. It does not wait for receipts — that is WitnessReceiptor's responsibility.
- **Does NOT own:** Receipt collection (WitnessReceiptor owns that). Witness pool definition (Kever.wits owns that).

---

**WitnessInquisitor**
- **Assembled From:** Habery, Deck (msgs)
- **Assembly Rationale:** WitnessInquisitor sends query messages to witnesses (or controllers or agents) to retrieve key event data or receipts. It is the "pull" half of the witness interaction model (WitnessPublisher is the "push" half). Habery provides endpoint role records to select the correct query target.
- **Invariants at Envelope Level:** Queries target a randomly selected witness from the AID's witness pool unless a specific target is provided. Failed queries are logged and retried on the next cycle. WitnessInquisitor does not interpret responses — it only sends queries.
- **Does NOT own:** Response parsing (Parser/Kevery own that). Query content construction (caller provides the query serder). Witness pool definition (Kever.wits owns that).

---

#### BC-6 — Verifiable Credentials (ACDC)

---

**ACDC (Authentic Chained Data Container)**
- **Assembled From:** SerderACDC (body), SAID, Seal (KEL anchor), Schemer (schema validator), Kever (issuer key state), Edge list
- **Assembly Rationale:** An ACDC combines the credential data (SerderACDC body), its self-certifying identity (SAID), its issuer authorization proof (Seal anchoring to KEL at the issuing key state), its structural conformance guarantee (Schemer), the verified issuer key state (Kever), and optional provenance chain (Edge list). Every component is necessary to establish the three-way trust: the issuer is who they say they are (Kever), the credential data is what it says it is (Schemer, SAID), and it was issued at a known key state (Seal).
- **Invariants at Envelope Level:** The ACDC SAID must match the Blake3-256 digest of the serialized body. The Seal's event SAID must appear in the issuer's KEL. The schema SAID in the `s` field must resolve to a valid JSON Schema document. An ACDC whose issuer's key state at the seal sequence number cannot be verified is not a valid ACDC.
- **Does NOT own:** Credential issuance workflow (VDR/TEL and Regery own that). Schema document authoring. Credential presentation protocol (IPEX owns that).

---

**VDR / TEL (Transaction Event Log)**
- **Assembled From:** Key Event (TEL variants: vcp/iss/rev), Tevery, Seal, Reger
- **Assembly Rationale:** The VDR/TEL mirrors the KEL structure for credential lifecycle events. Just as the KEL tracks AID key state, the TEL tracks credential issuance and revocation state. Each TEL event is anchored via Seal to the issuer's KEL, making the credential lifecycle traceable to the controller's key state. Tevery validates TEL events; Reger stores them; Seal provides the bridge to the KEL.
- **Invariants at Envelope Level:** `vcp` (registry inception) must precede any `iss` or `rev` events for that registry. Each `iss` event must be preceded by no prior `iss` for the same credential SAID. Each `rev` must be preceded by an `iss`. Every TEL event must have a corresponding Seal in the issuer's KEL. TEL event SAIDs are self-addressing.
- **Does NOT own:** ACDC content validation (Schemer owns that). Issuer AID key state (Kever owns that). Credential wallet (Regery/Registry own that).

---

**Regery (Registry Manager)**
- **Assembled From:** Reger, Tevery, Habery, Registry
- **Assembly Rationale:** Regery is the credential domain's equivalent of Habery: it provides the shared operational context for credential registry management. Reger is the database. Tevery is the event processor. Habery provides the controller context (which AID is the issuer). Registry objects represent individual credential registries. Together they constitute the minimal assembly needed to issue and revoke credentials.
- **Invariants at Envelope Level:** All Registry objects within one Regery share the same Reger and Tevery instances. A Registry may only be created for an AID that exists in the Habery. `Regery.inited` must be True before any credential operation. The `regs` dict keyed by registry key is the authoritative registry index.
- **Does NOT own:** IPEX protocol (vc/protocoling.py owns that). Credential wallet presentation logic. The controller AID key state (Habery/Kever own that).

---

**Reger (Registry Database)**
- **Assembled From:** LMDBer, TEL sub-tables
- **Assembly Rationale:** Reger is the credential domain's equivalent of Baser: a purpose-built LMDB database with sub-tables dedicated to credential lifecycle data. LMDBer provides the storage engine. TEL sub-tables store TEL events, registry state, credential issuance/revocation state, and TSN escrows. The separation from Baser keeps credential domain state isolated from identifier domain state.
- **Invariants at Envelope Level:** All TEL sub-table keys follow a composite key convention parallel to Baser's `dgKey`/`snKey`. The `tevers` dict provides a read-through cache of TEL state (parallel to Baser's `kevers`). Reger must be opened before Tevery is initialized.
- **Does NOT own:** Storage engine internals (LMDBer owns that). TEL event validation logic (Tevery owns that). Credential content (ACDC body is stored in Baser, not Reger).

---

**Tevery (TEL Event Processor)**
- **Assembled From:** Reger, Baser, Kever, Tever
- **Assembly Rationale:** Tevery is the TEL equivalent of Kevery. It validates incoming TEL events (vcp/iss/rev) against registry state, enforces the KEL-anchor requirement (using Baser and Kever to look up the issuer's KEL), and applies validated events to Tever state objects. Reger provides TEL storage. Tever is the in-memory TEL state object produced by Tevery.
- **Invariants at Envelope Level:** A TEL event is only applied after confirming that the corresponding Seal appears in the issuer's Baser (KEL). No TEL event modifies credential state without satisfying the anchor requirement. Tevery processes TEL events serially per registry key; concurrent processing is not supported.
- **Does NOT own:** Registry creation logic (Regery owns that). Credential content validation (Schemer owns that). Network I/O for fetching missing anchor events.

---

**Schemer (Credential Schema)**
- **Assembled From:** SAID, Baser (schema cache), JSON Schema Validator (external)
- **Assembly Rationale:** Schemer makes credential schemas first-class domain objects by combining content-addressable identity (SAID) with cached storage (Baser) and validation capability (jsonschema). A schema without a SAID is unverifiable. A schema without caching requires re-fetching on every validation. The SAID guarantees that the cached schema body is exactly what was committed to.
- **Invariants at Envelope Level:** `schemer.said` must match the Blake3-256 digest of the raw schema body. A Schemer retrieved from cache must have the same SAID as the lookup key. `schemer.verify(data)` raises `SchemaError` when the data does not conform to the JSON Schema document.
- **Does NOT own:** Schema resolution / fetching from remote OOBI (OOBI owns that). Credential attribute data (ACDC body owns that). SAID derivation algorithm (Diger/Matter own that).

---

**IPEX (Issuance and Presentation Exchange)**
- **Assembled From:** EXN (six message steps), SAID (chain link via `p` field), SerderACDC (grant payload), IpexHandler
- **Assembly Rationale:** IPEX structures credential exchange as a six-step protocol over authenticated `exn` messages. Each step's `p` field carries the SAID of the prior step, creating a cryptographically verifiable negotiation chain. The grant step embeds the full ACDC body (SerderACDC). IpexHandler registers handlers for each step route in the Exchanger. Without the chain-of-SAIDs invariant, steps could be replayed out of order or fabricated.
- **Invariants at Envelope Level:** Each step's `p` field must contain the SAID of the immediately preceding step in the same negotiation. A `grant` message must attach the full ACDC and its TEL proof. An `admit` is only valid in response to a `grant`. The exchange message timestamp must fall within `ExchangeMessageTimeWindow` (300 s). Spurn is valid in response to any step.
- **Does NOT own:** ACDC content validation (Schemer owns that). Credential storage (Regery owns that). Transport and routing (Exchanger and Protocol Message Channel port own that).

---

#### BC-7 — Peer Messaging

---

**EXN (Exchange Message)**
- **Assembled From:** SerderKERI (exn-ilk body), Siger list, Cigar list, Exchanger
- **Assembly Rationale:** An exchange message is a peer-to-peer authenticated envelope. The SerderKERI body carries the route, sender AID, timestamp, and payload. The Siger/Cigar lists provide the controller signatures. The Exchanger routes the assembled message to the correct domain handler. Without Exchanger, the message is merely a signed struct with no dispatch semantics.
- **Invariants at Envelope Level:** The sender AID (`i` field) must be verifiable against a known KEL. The message timestamp must be within `ExchangeMessageTimeWindow` of receipt time. The `r` (route) field must match a registered handler in the Exchanger. At least one valid signature (Siger or Cigar) must be present.
- **Does NOT own:** Handler-specific payload semantics (each handler owns its route's payload schema). Partial-signature escrow logic (Exchanger owns that). IPEX step chaining (IPEX owns that).

---

**Exchanger (EXN Router)**
- **Assembled From:** Kever (sender AID verification), Route handler registry, Partial-sig escrow (pses), Deck (cues)
- **Assembly Rationale:** Exchanger provides the dispatch backbone for all peer-to-peer protocol messages in keripy. Kever validates the sender AID before any handler is invoked. The handler registry maps route paths to behavior objects. The partial-sig escrow defers processing of group-signed messages until threshold is met. The cues Deck surfaces handler-generated notices.
- **Invariants at Envelope Level:** Each route path has at most one registered handler. Handlers may not be re-registered. The sender AID must be resolvable from `hby.db.kevers` before dispatch. Partially-signed messages that time out are discarded from the pses escrow.
- **Does NOT own:** Handler implementation logic (each handler owns its own invariants). Message serialization (Serder owns that). Network reception (Protocol Message Channel port owns that).

---

**Counselor (Multisig Coordinator)**
- **Assembled From:** Anchorer, WitnessInquisitor, Receiptor, GroupHab, Partial-sig escrow (gpse)
- **Assembly Rationale:** Counselor orchestrates the complete multi-party signing lifecycle for group events: collect partial signatures (gpse escrow), coordinate delegation anchor if delegated (Anchorer), query witnesses for missing receipts (WitnessInquisitor), and deliver the fully-signed receipted event (Receiptor). GroupHab provides the group identity context. No single component covers the full lifecycle; Counselor is the envelope that holds them in sequence.
- **Invariants at Envelope Level:** A group event is submitted to witnesses only after all required co-signer contributions have been collected in the gpse escrow. The `complete()` method is the authoritative check — it verifies both signatures and SAID. Anchorer's delegation loop must complete before the event is considered finalized for delegated groups.
- **Does NOT own:** Individual participant key management (each participant's Manager/Hab owns that). Witness pool selection (GroupHab's Kever owns that). Group event construction (GroupHab.makeOwnEvent owns that).

---

**Anchorer (Delegation Anchor Doer)**
- **Assembled From:** Poster, WitnessInquisitor, Receiptor, WitnessPublisher, Delegation partial-witness escrow (dpwe)
- **Assembly Rationale:** Anchorer serializes the two-sided delegation handshake. Poster sends the delegation notification `exn` to the delegator. WitnessPublisher + Receiptor send the delegatee event to witnesses and collect receipts. WitnessInquisitor queries the delegator's witnesses to detect when the anchor seal appears in the delegator's KEL. The dpwe escrow holds the delegatee event until the anchor is confirmed.
- **Invariants at Envelope Level:** The delegatee event (in dpwe) is not removed from escrow until the delegator's KEL contains a SealEvent matching the delegatee event's SAID. Anchorer exits Done only when the delegation is fully anchored. Multiple concurrent delegations are tracked by prefix in the `publishers` dict.
- **Does NOT own:** Delegator event construction (delegator's own Hab/Counselor own that). Anchor seal formation (delegator's Habery/Kevery own that). Network transport to delegator (Poster owns that).

---

### 6.4 New Absences Identified During Decomposition

The following concepts appeared as children in §6.2 trees but have no registry entry in Section 5.2. They are newly identified absent concepts (type: `unlisted`) and should be classified in the next iteration pass.

| Concept | Type | Appears In | Notes |
|---|---|---|---|
| `Dater` | unlisted | Kever | ISO datetime of first-seen event; hio Dater primitive used in Kever; not classified in §5 |
| `Broker` | unlisted | Escrow | TEL-side escrow sub-tables in `db/escrowing.py`; manages TSN (Transaction State Notice) escrows |
| `processEscrow*` methods | unlisted | Escrow | Nine named escrow evaluation methods in Kevery; behavioral logic without separate class concept |
| `Cuts / Adds` | unlisted | Rotation Event | Witness pool delta lists in rotation event body; not a named domain concept in §5 |
| `PubLot` (old/new/nxt) | unlisted | PubLot/PreSit | Individual dataclass instances within PreSit; all three PubLot fields lack §5 entries |
| `SAD dict` | unlisted | Serder | Deserialized event field map (plain Python dict); in-memory representation, not a typed domain concept |
| `50+ Baser sub-tables` | unlisted | Baser | Individual LMDB sub-tables (evts, fels, rcts, wigs, ldes, pses, etc.); infrastructure detail |
| `Filer` | unlisted | LMDBer | `hio.base.filing.Filer`; directory lifecycle for database paths |
| `Parser` | unlisted | Hab, Habery | `core/parsing.py`; message parser feeding Kevery; not classified in §5 |
| `Router / Revery` | unlisted | Habery | `core/routing.py`; reply-message routing; not classified in §5 |
| `Configer` | unlisted | Habery | `app/configing.py`; HJSON config file reader; not classified in §5 |
| `Encrypter` | unlisted | Manager | `core/coring.py`; AES-GCM encryption of private keys |
| `Decrypter` | unlisted | Manager | `core/coring.py`; AES-GCM decryption of private keys |
| `pris / pubs / gbls sub-tables` | unlisted | Keeper | LMDB sub-tables for private keys, public key sets, and global params; not individually classified in §5 |
| `Adjudicator` | unlisted | Watcher | `app/watching.py`; key state adjudication logic; named class but absent from §5 — candidate for classification |
| `OobiResolver` | unlisted | OOBI | `app/oobiing.py`; HTTP fetch + parse pipeline; named class but absent from §5 — candidate for classification |
| `Topic-keyed delivery index` | unlisted | Mailbox | LMDB IoSet sub-table for per-AID/per-topic message cursor tracking |
| `Tever` | unlisted | Tevery | `vdr/eventing.py`; in-memory TEL state object parallel to Kever; candidate for classification |
| `Registry` | unlisted | Regery | `vdr/credentialing.py`; per-registry context object; candidate for classification |
| `TEL sub-tables` | unlisted | Reger | Individual LMDB sub-tables for TEL events and credential state |
| `Edge list` | unlisted | ACDC | `e` field credential chain links in ACDC body; not a named §5 concept |
| `IpexHandler` | unlisted | IPEX | `vc/protocoling.py`; route-registered handler for each IPEX step; candidate for classification |
| `Route handler registry` | unlisted | Exchanger | Dict mapping route path strings to IHandler instances; internal to Exchanger |
| `Partial-sig escrow (pses)` | unlisted | Exchanger | Baser sub-table for partially-signed exn messages; referenced as named concept but not in §5 |
| `Receiptor` | unlisted | Counselor, Anchorer | `app/agenting.py:Receiptor`; sends events+receipts to witnesses; candidate for classification |
| `Poster` | unlisted | Anchorer | `app/forwarding.py`; sends exn delegation notification to delegator; absent from §5 |
| `dpwe escrow` | unlisted | Anchorer | `Baser.dpwe` sub-table; delegation partial-witness escrow; absent from §5 as named concept |

**Candidates for Section 5 classification in next pass (named classes, not just data structures):**
`Adjudicator`, `OobiResolver`, `Tever`, `Registry`, `IpexHandler`, `Receiptor`, `Poster`, `Parser`, `Router`, `Revery`, `Configer`, `Encrypter`, `Decrypter`, `Broker`

---

*End of Phase 4 output. Sections 7–9 to be produced in subsequent phases.*

---

## Section 7 — Target/Source Graph (Expected File Schema)

Derived from the concept model in Sections 5 and 6. The expected file schema is what the architecture *should* look like given the concept classifications — not a description of the current state. Isomorphism checks compare the expected schema against the actual keripy file graph.

**Table conventions:**
- File paths are relative to `src/keri/`.
- `[fn]` = concept expressed as functions, not a named class. `[db]` = concept expressed as LMDB sub-table schema. `[absent]` = concept expected but not present.
- Sources and consumers list domain-significant files only; `[ED-N]` notation flags external domain imports.
- Isomorphism verdict: **Pass** or **Fail**; Fail entries reference violation codes in §7.2.

---

### 7.1 File Schema Table

#### Group 1 — CESR Encoding (BC-3)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `core/coring.py` | Matter, Verfer, Diger, Cigar, Seqner, Prefixer, Tholder, SAID (Saider), Dater, AID/Prefixer | `kering.py`; [ED-1 pysodium, cryptography.hazmat]; [ED-2 blake3, hashlib]; [ED-6 cbor2, msgpack, json] | `core/eventing.py`, `core/signing.py`, `core/serdering.py`, `core/indexing.py`, `core/scheming.py`, `app/keeping.py`, `app/habbing.py`, + 100 files | **Fail** — V03, V04, V05 |
| `core/indexing.py` | Siger (Indexed Signature) | `core/coring.py`, `kering.py` | `core/eventing.py`, `core/signing.py`, `app/keeping.py` | **Pass** |
| `core/counting.py` | Counter (CESR Attachment Counter) | `kering.py` | `core/eventing.py`, `core/parsing.py`, `app/agenting.py` | **Pass** |
| `core/structing.py` | Seal (SealDigest, SealRoot, SealSource, SealEvent, SealLast, SealBack, SealKind) | `kering.py` | `core/eventing.py`, `vdr/eventing.py`, `app/delegating.py` | **Pass** |
| `core/serdering.py` | Serder, SerderKERI, SerderACDC, Version String/Versionage (partial) | `core/coring.py`, `core/counting.py`, `core/indexing.py`, `kering.py` | `core/eventing.py`, `app/habbing.py`, `vdr/eventing.py`, `vc/protocoling.py`, `peer/exchanging.py` | **Pass** |
| `kering.py` | Version String/Versionage, Ilks, Key Algorithm (Algos, partial), error taxonomy, TraitDex, Roles, Schemes | None (base constants module) | Virtually all domain files | **Pass** |

---

#### Group 2 — Event Processing (BC-1)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `core/eventing.py` | Kever, Kevery, Pre-rotation [fn], Duplicity [fn], KAWA/Witness Quorum [fn], TOAD [field], Key Event [fn], Inception Event [fn], Delegated Inception [fn], Rotation Event [fn], Delegated Rotation [fn], Interaction Event [fn], Receipt [fn] | `core/coring.py`, `core/counting.py`, `core/structing.py`, `core/indexing.py`, `core/serdering.py`, `db/` (Baser), `recording.py`, `kering.py`; [ED-5 hio.help.decking] | `app/habbing.py`, `app/agenting.py`, `app/grouping.py`, `app/delegating.py`, `app/oobiing.py`, `vdr/eventing.py`, `peer/exchanging.py` | **Pass** |
| `core/parsing.py` | Parser | `core/coring.py`, `core/counting.py`, `core/serdering.py`, `kering.py` | `app/habbing.py`, `app/agenting.py`, `app/oobiing.py`, `vdr/eventing.py` | **Pass** |
| `core/routing.py` | Router, Revery | `core/eventing.py`, `kering.py` | `app/habbing.py` | **Pass** |

---

#### Group 3 — Persistence (BC-4)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `db/basing.py` | Baser, Key Event Log [db], KERL [db] | `db/dbing.py`, `db/koming.py`, `db/subing.py`, `recording.py`, `kering.py`; [ED-3 lmdb ← VIOLATION] | `app/habbing.py`, `core/eventing.py`, `app/agenting.py`, `app/oobiing.py`, `vdr/eventing.py`, `vdr/credentialing.py` | **Fail** — V01 |
| `db/dbing.py` | LMDBer, Dber ABC [absent] | [ED-3 lmdb], [ED-5 hio.base.filing.Filer] | `db/basing.py`, `app/keeping.py`, `vdr/viring.py` | **Fail** — V02 |
| `db/koming.py` | Komer | `db/dbing.py`, `kering.py` | `db/basing.py`, `app/keeping.py`, `vdr/viring.py` | **Pass** |
| `db/escrowing.py` | Broker (TEL TSN escrow); Escrow [db — partial: KEL escrow sub-tables defined in Baser, not here] | `db/dbing.py`, `db/subing.py`, `kering.py` | `vdr/eventing.py` (Tevery) | **Fail** — V08 |
| `recording.py` | KeyStateRecord, OobiRecord, EndpointRecord | `kering.py` | `core/eventing.py`, `db/basing.py`, `app/habbing.py`, `app/oobiing.py`, `app/agenting.py` | **Pass** |

---

#### Group 4 — Key Management (BC-2)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `core/signing.py` | Salter, Encrypter, Decrypter, Security Tier (Tierage), Signer | `core/coring.py`, `core/indexing.py`, `kering.py`; [ED-1 pysodium, cryptography.hazmat] | `app/keeping.py`, `app/habbing.py` | **Fail** — V06 |
| `app/keeping.py` | Manager, Keeper, PubLot, PreSit, Key Algorithm (Algos) | `db/dbing.py`, `db/koming.py`, `core/signing.py`, `core/coring.py`, `kering.py`; [ED-1 pysodium] | `app/habbing.py` | **Fail** — V07 |
| `app/habbing.py` | Hab, Habery, GroupHab | `app/keeping.py`, `app/configing.py`, `db/basing.py`, `core/eventing.py`, `core/routing.py`, `core/parsing.py`, `peer/exchanging.py`, `recording.py` | `app/agenting.py`, `app/grouping.py`, `app/delegating.py`, `app/oobiing.py`, `vdr/credentialing.py`, `peer/exchanging.py`, CLI layer | **Pass** |
| `app/configing.py` | Configer | [ED-9 hjson]; [ED-5 hio.base.filing.Filer] | `app/habbing.py` | **Pass** |

---

#### Group 5 — Infrastructure Services (BC-5)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `app/agenting.py` | Receiptor, WitnessReceiptor, WitnessPublisher, WitnessInquisitor | `app/habbing.py`, `db/basing.py`, `core/eventing.py`; [ED-5 hio.base.doing, hio.help.decking] | `app/indirecting.py`, `app/grouping.py`, `app/delegating.py` | **Pass** |
| `app/indirecting.py` | Witness [assembled as `WitnessStart` — no named `Witness` class] | `app/agenting.py`, `app/habbing.py`, `core/eventing.py`, `core/parsing.py`; [ED-5 hio] | Startup scripts, CLI `witness` commands | **Fail** — V09 |
| `app/watching.py` | Adjudicator; Watcher [assembled — no named `Watcher` class] | `app/habbing.py`, `db/basing.py`; [ED-5 hio.help.decking] | CLI `local watch` commands | **Fail** — V10 |
| `app/oobiing.py` | OOBI (OobiResolver assembly: fetch + validate + store pipeline) | `core/eventing.py`, `core/parsing.py`, `core/routing.py`, `app/habbing.py`, `app/httping.py`, `recording.py`; [ED-4 falcon]; [ED-5 hio] | `app/habbing.py`, `app/agenting.py` | **Fail** — V11 |
| `app/storing.py` | Mailbox | `app/habbing.py`, `db/basing.py`; [ED-5 hio] | `app/agenting.py` | **Pass** |

---

#### Group 6 — Verifiable Credentials / ACDC (BC-6)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `core/scheming.py` | Schemer | `core/coring.py`, `db/basing.py`; [ED-7 jsonschema] | `app/oobiing.py`, `vdr/credentialing.py`, `vc/protocoling.py` | **Pass** |
| `vdr/eventing.py` | Tevery, Tever | `core/coring.py`, `core/eventing.py`, `db/basing.py`, `vdr/viring.py`, `kering.py`; [ED-5 hio] | `vdr/credentialing.py` | **Pass** |
| `vdr/viring.py` | Reger | `db/dbing.py`, `db/koming.py`, `db/subing.py`, `recording.py`, `kering.py` | `vdr/eventing.py`, `vdr/credentialing.py` | **Pass** |
| `vdr/credentialing.py` | Regery, Registry; ACDC [issuance authority] | `app/habbing.py`, `vdr/eventing.py`, `vdr/viring.py`, `core/scheming.py`, `core/serdering.py`; [ED-5 hio] | `vc/protocoling.py`, CLI `vc` commands | **Pass** |
| `vc/protocoling.py` | IPEX (IpexHandler); ACDC [exchange/presentation layer] | `peer/exchanging.py`, `vdr/credentialing.py`, `core/scheming.py`, `app/habbing.py` | `app/habbing.py`, CLI `ipex` commands | **Pass** |

---

#### Group 7 — Peer Messaging (BC-7)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `peer/exchanging.py` | Exchanger; EXN [dispatch + routing] | `app/habbing.py`, `core/eventing.py`, `core/serdering.py`, `db/basing.py`, `kering.py`; [ED-5 hio] | `app/habbing.py`, `app/grouping.py`, `vc/protocoling.py`, `app/challenging.py` | **Pass** |
| `app/grouping.py` | Counselor | `app/habbing.py`, `app/agenting.py`, `app/delegating.py`, `core/eventing.py`; [ED-5 hio] | CLI `group` commands, `app/habbing.py` | **Pass** |
| `app/delegating.py` | Anchorer; Delegation [orchestrated] | `app/habbing.py`, `app/agenting.py`, `app/forwarding.py`, `core/eventing.py`; [ED-5 hio] | `app/grouping.py`, CLI `delegate` commands | **Pass** |
| `app/forwarding.py` | Poster | `app/habbing.py`, `app/httping.py`; [ED-5 hio] | `app/delegating.py`, `app/grouping.py` | **Pass** |
| `app/challenging.py` | Challenge-Response | `app/habbing.py`, `core/eventing.py`, `peer/exchanging.py` | CLI `challenge` commands | **Pass** |
| `app/notifying.py` | Notifier | `db/basing.py`; [ED-5 hio] | `app/habbing.py`, `vc/protocoling.py`, `app/oobiing.py` | **Pass** |

---

#### Group 8 — Absent Concepts (no current file)

| Expected File | Owns Concept(s) | Key Sources | Key Consumers | Isomorphism |
|---|---|---|---|---|
| `core/ports.py` [absent] | Signing Oracle port (ED-1 port abstraction), Digest Oracle port (ED-2 port abstraction) | — | `core/coring.py`, `core/signing.py`, `app/keeping.py` | **Fail** — V12, V13 |
| `db/dbing.py:Dber` [absent] | Dber ABC (Durable Event Store port) | — | `db/dbing.py` (LMDBer), `db/basing.py`, `app/keeping.py`, `vdr/viring.py` | **Fail** — V02 (cross-referenced from Group 3) |

---

### 7.2 Isomorphism Violations

---

#### V01 — `db/basing.py` — Leakage (ED-3)

| Field | Value |
|---|---|
| **File** | `src/keri/db/basing.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import lmdb` at line 11 of `basing.py`. Baser directly calls LMDB APIs alongside LMDBer helper calls. The `db/` package's architectural intent is that `dbing.py:LMDBer` is the sole LMDB adapter; `Baser` should only call LMDBer helpers. |
| **Expected State** | `basing.py` imports no `lmdb` symbol directly. Any LMDB operation currently in Baser that bypasses LMDBer is moved into a new LMDBer helper method. |
| **Remediation** | Audit `basing.py` for direct `lmdb.*` calls. Move each to a named helper method on LMDBer (e.g., `LMDBer.putIoSetVals`, `LMDBer.trimIoSet`). Remove `import lmdb` from `basing.py`. This is a low-risk, incremental change confined to two files. |

---

#### V02 — `db/dbing.py` — Absent (Durable Event Store port)

| Field | Value |
|---|---|
| **File** | `src/keri/db/dbing.py` [expected class `Dber`] |
| **Violation Type** | Absent (named but unbuilt) |
| **Evidence** | `LMDBer` is the concrete storage engine wrapper. No `Dber` ABC (abstract base class) or `Protocol` exists to formalize the port interface. `Baser`, `Keeper`, and `Reger` all inherit from `LMDBer` directly, making the LMDB engine a structural constraint rather than a substitutable dependency. |
| **Expected State** | `db/dbing.py` defines an abstract `Dber` base class with all helper-method signatures (`getVal`, `putVal`, `delVal`, `getIoVals`, `putIoVals`, `delIoVals`, transaction context methods, etc.). `LMDBer` implements `Dber`. `Baser`, `Keeper`, and `Reger` declare their base type as `Dber`, not `LMDBer`. |
| **Remediation** | Add `class Dber(ABC)` to `db/dbing.py` with abstract method signatures matching `LMDBer`'s public interface. Have `LMDBer` implement it. Update `Baser(dbing.LMDBer)`, `Keeper(dbing.LMDBer)`, and `Reger(dbing.LMDBer)` to extend `dbing.Dber`. This enables in-memory (`MemDber`) and mock database adapters for testing. Medium-effort change; backward-compatible if done incrementally. |

---

#### V03 — `core/coring.py` — Leakage (ED-1: Signing Oracle)

| Field | Value |
|---|---|
| **File** | `src/keri/core/coring.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import pysodium` (line 16) and `from cryptography.hazmat.*` (lines 20–22) in `coring.py`. `pysodium` is called inside `Verfer.verify()` for Ed25519 signature verification. `cryptography.hazmat` is called for ECDSA P-256, secp256k1, and Ed448 verification. These are concrete signing algorithm implementations embedded in the CESR primitive layer. |
| **Expected State** | `coring.py` imports no `pysodium` or `cryptography` symbol. `Verfer.verify()` dispatches to a `SigningOracle` port (abstract). Each algorithm (Ed25519, ECDSA-P256, ECDSA-k1, Ed448) is implemented in a named adapter class in `core/signing.py`. |
| **Remediation** | Define `SigningOracle` ABC in `core/ports.py` (or `core/signing.py`). Extract the algorithm dispatch table in `Verfer.verify()` into algorithm-specific `Signer`/`Verifier` adapter classes. Wire via a registry keyed by CESR type code. High-effort structural change; can be done in phases (Ed25519 first, then ECDSA variants). |

---

#### V04 — `core/coring.py` — Leakage (ED-2: Digest Oracle)

| Field | Value |
|---|---|
| **File** | `src/keri/core/coring.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import blake3` (line 17) and `import hashlib` (line 18) in `coring.py`. Both are called directly inside `Diger.__init__()` and `Diger.verify()` via a type-code-to-constructor dispatch table that maps CESR digest codes (Blake3-256, Blake2b-256, SHA-256, SHA3-256, SHA3-512) to concrete hash library calls. |
| **Expected State** | `coring.py` imports no `blake3` or `hashlib` symbol. `Diger` dispatches to a `DigestOracle` port. Each hash algorithm is implemented in a named adapter class. |
| **Remediation** | Define `DigestOracle` ABC in `core/ports.py`. Extract `Diger`'s algorithm dispatch table into named digest adapter classes. Wire via registry. Medium-effort; can be done per-algorithm. |

---

#### V05 — `core/coring.py` — Leakage (ED-6: Serialization Format Codec)

| Field | Value |
|---|---|
| **File** | `src/keri/core/coring.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import cbor2 as cbor` (line 14) and `import msgpack` (line 15) in `coring.py`. These serialization library imports are present in the CESR primitive base file, co-located with `Matter`, `Verfer`, `Diger`, etc. The intended serialization boundary is `core/serdering.py` (`Serder.loads`/`Serder.dumps`). |
| **Expected State** | `coring.py` imports no `cbor2` or `msgpack` symbol. All multi-format codec logic is confined to `core/serdering.py:Serder`. |
| **Remediation** | Audit uses of `cbor2` and `msgpack` in `coring.py`. If any exist outside Serder-related code paths, move them to `serdering.py`. Remove serialization imports from `coring.py` if unused. Low-to-medium effort; likely small scope. |

---

#### V06 — `core/signing.py` — Leakage (ED-1: Signing Oracle)

| Field | Value |
|---|---|
| **File** | `src/keri/core/signing.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import pysodium` (line 10) and `from cryptography.hazmat.*` (lines 12–14) in `signing.py`. `pysodium` is called inside `Salter` for Argon2 key stretching, Ed25519 seed derivation, and random byte generation. `cryptography.hazmat` is called inside `Encrypter` and `Decrypter` for AES-GCM and ECDH operations. These are algorithm implementations embedded in domain-named classes. |
| **Expected State** | `signing.py` contains `Salter`, `Encrypter`, `Decrypter` as domain classes. Their algorithm-specific calls are delegated to named adapter classes or dispatched via `SigningOracle` port. `pysodium` and `cryptography` are imported only in adapter files. |
| **Remediation** | Same remediation pathway as V03. As part of implementing `SigningOracle`, extract Argon2, AES-GCM, and ECDH operations into named adapters. `Salter` and `Encrypter`/`Decrypter` become thin orchestrators that call the port. |

---

#### V07 — `app/keeping.py` — Leakage (ED-1: Signing Oracle)

| Field | Value |
|---|---|
| **File** | `src/keri/app/keeping.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import pysodium` at line 29 of `keeping.py`. `pysodium` is called directly inside `Manager` for key derivation and cryptographic operations. This extends the ED-1 leakage beyond the `core/` layer into the key management application layer. |
| **Expected State** | `keeping.py` imports no `pysodium` symbol. `Manager`'s cryptographic calls route through `core/signing.py:Salter` and `core/signing.py:Encrypter`/`Decrypter`, which are themselves being cleaned up under V06. Manager never calls a cryptographic library directly. |
| **Remediation** | Identify each `pysodium.*` call in `keeping.py`. Route each through the appropriate `Salter`, `Encrypter`, or `Decrypter` method in `core/signing.py`. Remove `import pysodium` from `keeping.py`. Low-effort once V06 adapters are in place. |

---

#### V08 — `core/eventing.py` + `db/basing.py` — Fragmentation (KEL Escrow)

| Field | Value |
|---|---|
| **Files** | `src/keri/core/eventing.py` (processEscrow* methods in Kevery), `src/keri/db/basing.py` (KEL escrow sub-table definitions as Baser attributes) |
| **Violation Type** | Fragmentation (missing joint) |
| **Evidence** | The BC-1 Escrow concept has no authoritative named owner. The nine KEL escrow buckets (OOE, PSE, PWE, LDE, UWE, URE, VRE, KSN, QNF) are defined as `IoSetSuber` attributes of `Baser` in `basing.py`. The policy logic — `processEscrow*` evaluation methods, timeout constants — lives inside `Kevery` in `eventing.py`. The two are bound at Kevery construction time with no mediating class. Note: `db/escrowing.py:Broker` is the TEL TSN escrow (for `Tevery`), not the KEL escrow, so it does not resolve this gap. |
| **Expected State** | Either (a) a named `KelEscrow` class in `core/eventing.py` encapsulates all nine bucket names, timeout constants, and `processEscrow*` methods and is assembled by Kevery; or (b) the sub-table definitions and processEscrow methods are co-located in a dedicated `core/escrowing.py` module that Kevery imports. Either resolution gives the KEL Escrow concept a single named, discoverable home. |
| **Remediation** | Extract the nine `processEscrow*` methods, their timeout constants, and their bucket name literals from `Kevery` into a `KelEscrowManager` (or similar) class in `core/eventing.py` or a new `core/escrowing.py`. Kevery holds a reference to this class. Baser sub-table definitions remain in `basing.py` (correct owner), but Kevery accesses them via the escrow manager. Medium-effort refactor; high value for discoverability. |

---

#### V09 — `app/indirecting.py` — Misplaced Authority (Witness)

| Field | Value |
|---|---|
| **File** | `src/keri/app/indirecting.py` |
| **Violation Type** | Misplaced authority |
| **Evidence** | The KERI spec and Section 3.3 (BC-5) both name `Witness` as a first-class infrastructure concept. No class named `Witness` (or `WitnessNode`) exists. The concept is assembled by `WitnessStart(doing.DoDoer)` in `indirecting.py` — a startup/wiring module — as an incidental composition. A consumer cannot import `Witness` as a named type. |
| **Expected State** | A named class `Witness` (or `WitnessNode`) exists in `app/indirecting.py` or a dedicated `app/witnessing.py`. It composes `WitnessReceiptor` + `WitnessPublisher` + `WitnessInquisitor` + `Kevery` and exposes the domain concept under its spec name. |
| **Remediation** | Rename `WitnessStart` to `Witness` (or create a thin `Witness` wrapper class that documents its assembly contract). If the DoDoer structural requirement conflicts with the naming, create a named `Witness` dataclass/namedtuple that describes the composition, and have `WitnessStart` instantiate it. Low-effort: primarily a naming and documentation change. |

---

#### V10 — `app/watching.py` — Misplaced Authority (Watcher)

| Field | Value |
|---|---|
| **File** | `src/keri/app/watching.py` |
| **Violation Type** | Misplaced authority |
| **Evidence** | The KERI spec and Section 3.3 (BC-5) name `Watcher` as a first-class infrastructure concept. No class named `Watcher` exists. `app/watching.py` contains `Adjudicator` — one component of the Watcher concept — but the Watcher envelope (Adjudicator + WitnessInquisitor + Kevery assembly) has no named class. A developer looking for "Watcher" finds `Adjudicator`, which is semantically distinct. |
| **Expected State** | A named class `Watcher` in `app/watching.py` that assembles `Adjudicator` + `WitnessInquisitor` + `Kevery` and represents the complete watcher infrastructure node concept. |
| **Remediation** | Create a named `Watcher` class (or `WatcherDoer`) in `app/watching.py` that composes `Adjudicator`, `WitnessInquisitor`, and a validator-mode `Kevery`. This gives the spec concept a physical home. Low-effort: additive, does not break existing callers. |

---

#### V11 — `app/oobiing.py` — Leakage (ED-4: HTTP Transport)

| Field | Value |
|---|---|
| **File** | `src/keri/app/oobiing.py` |
| **Violation Type** | Leakage |
| **Evidence** | `import falcon` at line 13 of `oobiing.py`. Falcon (HTTP routing framework) is imported directly in the domain OOBI resolution module. `oobiing.py` uses Falcon `Request`/`Response` types for endpoint handler methods, coupling the OOBI domain concept to the HTTP transport framework. |
| **Expected State** | `oobiing.py` imports no `falcon` symbol. HTTP endpoint handlers that currently live in `oobiing.py` are extracted to `app/httping.py` or an `end/` adapter file. The OOBI resolution logic (fetch URL, parse KEL stream, validate, store) is invokable independently of the HTTP framework. |
| **Remediation** | Extract Falcon endpoint classes from `oobiing.py` into `end/ending.py` or `app/httping.py` (the intended HTTP adapter boundary). `oobiing.py` retains only the domain OOBI resolution pipeline (OobiResolver: fetch → parse → validate → store). Medium-effort; the split between domain logic and HTTP handler is already partially present in the codebase pattern. |

---

#### V12 — `[absent]` — Absent (Signing Oracle Port)

| Field | Value |
|---|---|
| **File** | Expected: `src/keri/core/ports.py` or `src/keri/core/signing.py` [absent class `SigningOracle`] |
| **Violation Type** | Absent (named but unbuilt) |
| **Evidence** | ED-1 (Cryptographic Signature Primitives) is documented in Section 4.1 with a named port concept "Signing Oracle". No `SigningOracle` ABC or `Protocol` class exists. Without this port, the domain cannot substitute the signing backend (e.g., for HSM integration, testing, or algorithm migration) without modifying domain files. |
| **Expected State** | A `SigningOracle` abstract class (or `Protocol`) in `core/ports.py` defines the interface: `sign(msg: bytes, algo: str) -> bytes`, `verify(sig: bytes, msg: bytes, key: bytes, algo: str) -> bool`, `derive(seed: bytes, algo: str) -> tuple[bytes, bytes]`. Concrete implementations for `pysodium` (Ed25519, X25519, Argon2) and `cryptography` (ECDSA-P256, ECDSA-k1, Ed448) live in separate adapter classes. |
| **Remediation** | Create `src/keri/core/ports.py` with `SigningOracle` ABC. Implement `PysodiumSigningAdapter` and `CryptographySigningAdapter`. Wire into `Verfer`, `Salter`, `Encrypter`, `Decrypter` via constructor injection or a type-code-keyed registry. This is prerequisite to fixing V03, V06, V07. High-effort; prioritize per-algorithm. |

---

#### V13 — `[absent]` — Absent (Digest Oracle Port)

| Field | Value |
|---|---|
| **File** | Expected: `src/keri/core/ports.py` [absent class `DigestOracle`] |
| **Violation Type** | Absent (named but unbuilt) |
| **Evidence** | ED-2 (Cryptographic Digest Computation) is documented in Section 4.1 with a named port concept "Digest Oracle". No `DigestOracle` ABC or `Protocol` class exists. `blake3` and `hashlib` are called directly from within `Diger` in `core/coring.py`. |
| **Expected State** | A `DigestOracle` abstract class in `core/ports.py` defines: `digest(data: bytes, algo: str) -> bytes`, `verify(data: bytes, digest: bytes, algo: str) -> bool`. Concrete implementations (`Blake3DigestAdapter`, `HashlibDigestAdapter`) live in a `core/` adapter file. |
| **Remediation** | Add `DigestOracle` ABC to `core/ports.py` alongside `SigningOracle`. Implement adapters. Wire into `Diger` via type-code-keyed registry. Prerequisite to fixing V04. Medium-effort. |

---

### 7.3 Ownership Invariants

The following invariants must hold in the target architecture. The first four are the standard structural invariants derived from the ports-and-adapters classification system (§10 of the classification system document). The remainder are domain-specific invariants for keripy.

---

**INV-1 (Standard): Domain logic files must not import external domain libraries directly.**

No file outside of `core/ports.py` (port definitions), designated adapter classes, or the `db/dbing.py` LMDB adapter may import `pysodium`, `blake3`, `hashlib`, `lmdb`, `falcon`, `cbor2`, `msgpack`, `jsonschema`, `hjson`, or `http_sfv`. Any such import is a leakage violation.

*Currently violated by: V01, V03, V04, V05, V06, V07, V11.*

---

**INV-2 (Standard): All external domain access must route through named port abstractions.**

Every external domain (ED-1 through ED-9) must have a corresponding named port abstraction (ABC or `Protocol` class) in the keripy codebase. Domain logic classes invoke only the port interface, never the concrete adapter. Port names: `SigningOracle`, `DigestOracle`, `DurableEventStore`, `ProtocolMessageChannel`, `AsyncTaskScheduler`, `SerializationFormatCodec`, `CredentialSchemaValidator`, `HttpSignatureHeaderCodec`, `ConfigurationSource`.

*Currently violated by: V02, V12, V13 (absent ports). ED-5 through ED-9 also lack port abstractions but at lower leakage risk.*

---

**INV-3 (Standard): Port abstractions use only domain-language types in their method signatures.**

A port method signature must not include external library types (e.g., `lmdb.Transaction`, `falcon.Request`, `hio.base.doing.Doer`) as parameter or return types. It may only reference domain primitives (`bytes`, `str`, `int`, CESR-typed classes, dataclasses from `recording.py`).

*Currently not assessable: no port abstractions exist to violate this invariant. Prerequisite to V02, V12, V13 remediation.*

---

**INV-4 (Standard): Only designated adapter files may call external domain APIs directly.**

Adapter files for each external domain must be single, named, explicitly documented boundary files. Current target assignments: `db/dbing.py` (LMDB); `core/signing.py` algorithm adapter classes (pysodium, cryptography); `core/counting.py` + `core/serdering.py` (json/cbor2/msgpack); `core/scheming.py` (jsonschema); `app/configing.py` (hjson); `end/ending.py` (http_sfv, falcon HTTP signatures); `app/httping.py` (falcon HTTP routing).

*Currently violated by V01, V03, V04, V05, V06, V07, V11: external calls exist in non-adapter files.*

---

**INV-5 (Domain): All AID key state changes are applied exclusively through `Kever.__init__()` or `Kever.update()`.**

No code path may directly mutate `Kever` fields (`verfers`, `ndigers`, `tholder`, `wits`, `toader`, `sn`, `prefixer`). All state transitions must pass through the two entry points, which enforce signature threshold verification, pre-rotation satisfaction, and chaining digest checks before writing. Direct field mutation bypasses these invariants.

---

**INV-6 (Domain): Private key bytes must never be persisted in plaintext or transmitted outside the process.**

Within `Manager`, raw private key bytes must be encrypted (AES-GCM via `Encrypter`) before any persistence call to `Keeper`. All decryption (`Decrypter`) produces transient bytes that must be zeroed after signing. No `logging`, serialization, or network call may receive unencrypted key material as an argument.

---

**INV-7 (Domain): No non-idempotent database write may occur for an event that fails validation.**

Inside `Kevery.processEvent()`, all database writes for a given event must be transactionally guarded: if any validation check fails (signature threshold, chaining digest, pre-rotation satisfaction, duplicity detection), no persistent state is written for that event. The event is routed to the appropriate escrow or discarded, not partially applied.

---

**INV-8 (Domain): A delegated inception/rotation event must not produce a Kever state change until the delegator anchor seal is confirmed.**

For `dip` and `drt` events, `Kever.__init__()`/`Kever.update()` must not complete (no persistent state written) until `Kevery` has confirmed that the delegator's KEL contains a `SealEvent` referencing the delegatee event's SAID. The event must wait in the delegation partial-witness escrow (`Baser.dpwe`) until this condition is satisfied.

---

**INV-9 (Domain): An AID prefix is immutable after inception.**

`Kever.prefixer.qb64` must never change after the inception event is applied. No rotation, interaction, or delegation event may alter the AID prefix. Any code path that would overwrite `Kever.prefixer` is a protocol violation.

---

**INV-10 (Domain): LMDB operations must only be called from `LMDBer` methods — never from domain logic above `db/dbing.py`.**

No class outside the `db/` package may call `lmdb.Environment`, `lmdb.Transaction`, or `lmdb.Cursor` APIs directly. All database operations in `Baser`, `Keeper`, and `Reger` must invoke the helper methods on their `LMDBer` base. This enforces the `db/dbing.py` adapter boundary and is the runtime counterpart to INV-1 for the persistence domain.

*Currently violated by V01 (`basing.py` direct `lmdb` import).*

---

**INV-11 (Domain): The KEL for any AID is append-only; no event at sequence number `n` may be modified or deleted once written.**

`Baser.evts`, `Baser.fels`, and `Baser.dtss` sub-tables are write-once per `dgKey`/`snKey`. No update or delete operation may target an already-written event record. Escrow sub-tables are the only storage that supports modification (write and delete for re-evaluation). This invariant underlies the tamper-evidence guarantee of the KEL.

---

*End of Phase 5 output. Sections 8–9 to be produced in subsequent phases.*

---

## Section 8 — Absence and Cross-Cut Report

### 8.1 Absence Report

Thirteen absent concepts are documented for Pass 1. Four were identified in §5.4; nine are newly surfaced from §6.4 decomposition trees and §7 isomorphism analysis.

---

#### A01 — Dber ABC (Durable Event Store Port)

| Field | Value |
|---|---|
| **Concept Name** | Dber ABC |
| **Absence Type** | Named but unbuilt |
| **Spec Evidence** | §4.1 ED-3 documents the "Durable Event Store" port concept. §5.4 records V02: no `ABC` or `Protocol` class for storage interface. §7.1 Group 8 lists expected file `db/dbing.py:Dber [absent]`. §7.2 V02 provides full remediation path. Project memory records this as the first violation confirmed in the codebase. |
| **Resolution** | **Build** — Medium effort. Add `class Dber(ABC)` to `db/dbing.py`. Have `LMDBer` implement it. Update `Baser`, `Keeper`, and `Reger` to declare `Dber` as base type. Unblocks in-memory and mock storage adapters needed for fast unit tests. |

---

#### A02 — SigningOracle Port

| Field | Value |
|---|---|
| **Concept Name** | SigningOracle Port |
| **Absence Type** | Named but unbuilt |
| **Spec Evidence** | §4.1 ED-1 names the "Signing Oracle" port. §7.2 V12 documents the absence. No `SigningOracle` ABC or `Protocol` class exists anywhere in the keripy source tree. `pysodium` and `cryptography.hazmat` are imported directly in `core/coring.py` (V03), `core/signing.py` (V06), and `app/keeping.py` (V07) with no intervening abstraction. |
| **Resolution** | **Build** — High effort; prerequisite to fixing V03, V06, V07. Create `src/keri/core/ports.py` containing `SigningOracle` ABC with abstract method signatures `sign()`, `verify()`, `derive()`. Implement `PysodiumSigningAdapter` and `CryptographySigningAdapter`. Wire into `Verfer`, `Salter`, `Encrypter`, `Decrypter`. Tackle per algorithm suite to contain scope. |

---

#### A03 — DigestOracle Port

| Field | Value |
|---|---|
| **Concept Name** | DigestOracle Port |
| **Absence Type** | Named but unbuilt |
| **Spec Evidence** | §4.1 ED-2 names the "Digest Oracle" port. §7.2 V13 documents the absence. No `DigestOracle` ABC or `Protocol` class exists. `blake3` and `hashlib` are imported and called directly inside `Diger.__init__()` and `Diger.verify()` in `core/coring.py` (V04). |
| **Resolution** | **Build** — Medium effort. Add `DigestOracle` ABC to `core/ports.py` alongside `SigningOracle`. Implement `Blake3DigestAdapter` and `HashlibDigestAdapter`. Wire into `Diger` via CESR type-code–keyed registry. Prerequisite to fixing V04. |

---

#### A04 — Witness (Named Class)

| Field | Value |
|---|---|
| **Concept Name** | Witness (named class) |
| **Absence Type** | Missing part |
| **Spec Evidence** | KERI specification names Witness as a first-class infrastructure role. §5.2 BC-5 classifies `Witness` as `core | complex | composite` and documents: "Physical note: No named `Witness` class exists. The concept is assembled by `WitnessStart` (`app/indirecting.py:146`)." §7.2 V09 formally records the misplaced authority violation. |
| **Resolution** | **Build** — Low effort. Rename `WitnessStart` to `Witness` in `app/indirecting.py`, or create a thin `Witness` wrapper class that assembles the four Doers (WitnessReceiptor, WitnessPublisher, WitnessInquisitor, Kevery) and documents the assembly contract under the spec-defined name. |

---

#### A05 — Watcher (Named Class)

| Field | Value |
|---|---|
| **Concept Name** | Watcher (named class) |
| **Absence Type** | Missing part |
| **Spec Evidence** | KERI specification names Watcher as a first-class infrastructure role. §5.2 BC-5 classifies `Watcher` as `core | substantive | composite` and notes: "No named `Watcher` class. The concept is assembled from `Adjudicator` + `WitnessInquisitor` + `Kevery` in `app/watching.py`." §7.2 V10 records the misplaced authority violation. |
| **Resolution** | **Build** — Low effort. Create a named `Watcher` class (or `WatcherDoer`) in `app/watching.py` that composes `Adjudicator`, `WitnessInquisitor`, and a validator-mode `Kevery`. Additive change; does not break existing callers. |

---

#### A06 — KelEscrowManager (KEL Escrow Joint)

| Field | Value |
|---|---|
| **Concept Name** | KelEscrowManager |
| **Absence Type** | Missing joint |
| **Spec Evidence** | §5.2 BC-1 classifies `Escrow` as `core | substantive | composite`. §6.2 Escrow decomposition identifies the split: nine KEL escrow sub-table definitions reside in `Baser` (basing.py) while the nine `processEscrow*` methods and timeout constants reside in `Kevery` (eventing.py). §7.2 V08 documents the fragmentation and names the resolution: a `KelEscrowManager` class or equivalent mediating class. The TEL-side `Broker` in `db/escrowing.py` does NOT cover this gap — it is scoped to Tevery only. |
| **Resolution** | **Build** — Medium effort. Extract `processEscrow*` methods, timeout constants, and bucket name literals from `Kevery` into a `KelEscrowManager` class in `core/eventing.py` or a new `core/escrowing.py`. `Kevery` holds a reference. Baser sub-table definitions remain in `basing.py`. |

---

#### A07 — Tever (TEL Key State Object)

| Field | Value |
|---|---|
| **Concept Name** | Tever |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `Tever` as an unlisted concept: "in-memory TEL state object parallel to Kever; `vdr/eventing.py:Tever`; candidate for classification." ACDC/TEL specification implies per-registry and per-credential state tracking must be maintained in memory during processing. The `Tevery` concept card (§5.3 BC-6) references Tever as a child but Tever has no §5 registry entry. |
| **Resolution** | **Build** — Classify `Tever` in §5 Pass 2 as `core | substantive | composite` in BC-6. File owner: `vdr/eventing.py`. Disposition: `dark` (code-only, no spec name). |

---

#### A08 — Parser (Message Parser)

| Field | Value |
|---|---|
| **Concept Name** | Parser |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `Parser` as unlisted: "core/parsing.py; message parser feeding Kevery; not classified in §5." Parser is referenced in `Hab` decomposition (§6.2) and `Habery` decomposition as a critical assembly component. All Hab and infrastructure nodes depend on Parser to deserialize incoming KERI/CESR message streams before Kevery processes them. |
| **Resolution** | **Build** — Classify `Parser` in §5 Pass 2 as `core | substantive | composite` in BC-1. File owner: `core/parsing.py`. Disposition: `dark` (code-only, not named in spec). |

---

#### A09 — Adjudicator (Key State Adjudicator)

| Field | Value |
|---|---|
| **Concept Name** | Adjudicator |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `Adjudicator` as unlisted: "`app/watching.py:37`; key state adjudication logic; named class but absent from §5 — candidate for classification." `Adjudicator` is referenced in the `Watcher` decomposition (§6.2 BC-5). The KERI specification implies that a watcher must compare multi-source key state reports to detect inconsistency — the adjudication logic. Project memory confirms location at `app/watching.py:37`. |
| **Resolution** | **Build** — Classify `Adjudicator` in §5 Pass 2 as `core | non-trivial | composite` in BC-5. File owner: `app/watching.py`. Disposition: `dark`. Also required for A05 resolution: `Watcher` class wraps `Adjudicator`. |

---

#### A10 — OobiResolver

| Field | Value |
|---|---|
| **Concept Name** | OobiResolver |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `OobiResolver` as unlisted: "`app/oobiing.py`; HTTP fetch + parse pipeline for OOBI resolution; named class but absent from §5 — candidate for classification." The `OOBI` composite decomposition (§6.2 BC-5) lists `OobiResolver` as a leaf node: "HTTP fetch + parse pipeline for OOBI resolution." §7.2 V11 documents that `oobiing.py` has a `falcon` leakage; the resolution pipeline should be extractable without Falcon coupling. |
| **Resolution** | **Build** — Classify `OobiResolver` in §5 Pass 2 as `core | non-trivial | composite` in BC-5. File owner: `app/oobiing.py`. Disposition: `dark`. Extraction of the resolution pipeline from Falcon coupling (per V11 remediation) is a parallel concern. |

---

#### A11 — IpexHandler

| Field | Value |
|---|---|
| **Concept Name** | IpexHandler |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `IpexHandler` as unlisted: "`vc/protocoling.py`; route-registered handler dispatching each IPEX step; candidate for classification." The `IPEX` concept card (§5.3 BC-6) references `IpexHandler` as a leaf assembly component. IPEX (Issuance and Presentation Exchange) is a spec-defined six-step protocol; `IpexHandler` is the code's named dispatch class for it. |
| **Resolution** | **Build** — Classify `IpexHandler` in §5 Pass 2 as `core | substantive | composite` in BC-6. File owner: `vc/protocoling.py`. Disposition: `dark`. |

---

#### A12 — Receiptor

| Field | Value |
|---|---|
| **Concept Name** | Receiptor |
| **Absence Type** | Missing part (in code; absent from §5 concept registry) |
| **Spec Evidence** | §6.4 lists `Receiptor` as unlisted: "`app/agenting.py:Receiptor`; sends events+receipts to witnesses; candidate for classification." `Receiptor` is referenced as a child in both `Counselor` (§6.2 BC-7) and `Anchorer` (§6.2 BC-7) decomposition trees. It is a named class in `app/agenting.py` alongside `WitnessReceiptor` and `WitnessPublisher`. |
| **Resolution** | **Build** — Classify `Receiptor` in §5 Pass 2 as `core | non-trivial | composite` in BC-5 or BC-7. File owner: `app/agenting.py`. Disposition: `dark`. Differentiate clearly from `WitnessReceiptor`: `Receiptor` sends assembled events+receipts; `WitnessReceiptor` handles the collection cycle. |

---

#### A13 — Validator (Named Role)

| Field | Value |
|---|---|
| **Concept Name** | Validator |
| **Absence Type** | Assumed but unspecced |
| **Spec Evidence** | The KERI specification describes "validator" as a first-class role distinct from witness and controller. A validator applies the first-seen rule, enforces TOAD quorum for witnessed events, and detects duplicity. In keripy this role is split across `Kevery` (event validation mode), `Adjudicator` (key state adjudication in watcher context), and `Kever` (key state enforcement). No named `Validator` class exists or is needed for the current architecture — the concept is fully expressed through its component parts. |
| **Resolution** | **Defer** — The validator role is adequately realized through `Kevery` in validator mode plus `Adjudicator`. Introducing a `Validator` wrapper class would add organizational overhead without changing behavior or enabling substitution. Revisit if the spec formalization of validator-specific invariants grows beyond what `Kevery`/`Adjudicator` can express. |

---

### 8.2 Cross-Cut Report

Four concepts exhibit high fan-in across unrelated bounded contexts. Two (Baser, Kever) are cross-cut by design and should be formalized as shared kernel components. Two (hio Doer, Serder) require distinct treatment.

---

#### CC-1 — Baser (KERI Event Database)

| Field | Value |
|---|---|
| **Concept Name** | Baser |
| **Cross-Cut Type** | Infrastructural |
| **Fan-In Count** | 7 (all bounded contexts directly reference `Baser` or its sub-tables) |
| **Current Owner** | BC-4 Persistence |
| **Resolution** | **Shared kernel** — Baser's universal fan-in is intentional: it is the protocol's single durable state store, and all domain operations (event processing, key management, credential lifecycle, infrastructure services, peer messaging) must read from or write to it. Baser should be explicitly declared a **shared kernel** component in the §3.3 bounded context descriptions. BC-4 retains ownership authority (schema definition, sub-table lifecycle, migration). All other BCs are consumers. Ownership invariant: only BC-4 may add new sub-tables; other BCs may only access Baser through named helper methods. |

---

#### CC-2 — Kever (Key State)

| Field | Value |
|---|---|
| **Concept Name** | Kever |
| **Cross-Cut Type** | Implicit |
| **Fan-In Count** | 6 (BC-1 creates/mutates; BC-2 reads via Hab; BC-5 Witness/Watcher validate using; BC-6 verifies issuer key state; BC-7 EXN sender validation; BC-4 persists as KeyStateRecord) |
| **Current Owner** | BC-1 Event Processing |
| **Resolution** | **Name & classify** as a cross-BC **value object** shared via read-only access. BC-1 retains exclusive mutation authority (`Kever.__init__()` and `Kever.update()` are the only valid entry points — INV-5). All other BCs treat Kever as a read-only domain value object: they may inspect its fields but must never mutate them. Add to §3.3: "Kever is a shared read-only value object; all Kever mutation must route through BC-1 Kevery." |

---

#### CC-3 — hio Doer Pattern

| Field | Value |
|---|---|
| **Concept Name** | hio Doer (Asynchronous Task Scaffold) |
| **Cross-Cut Type** | Infrastructural (external framework constraint) |
| **Fan-In Count** | 7 (124 files across all BCs; virtually the entire application layer) |
| **Current Owner** | ED-5 (external; no internal domain owner) |
| **Resolution** | **Redirect** — The hio Doer generator protocol is an external framework constraint that has been absorbed into the domain class design as a structural scaffold. The correct resolution is INV-2: define an `AsyncTaskScheduler` port (`core/ports.py`) and declare domain task classes against the port interface rather than directly against `hio.base.doing.Doer`. This is the highest-leverage single change for the entire cross-cut surface: once the port exists, hio can be substituted (e.g., for asyncio) without modifying domain classes. Until the port is built, the cross-cut remains an accepted architectural debt item documented under ED-5. |

---

#### CC-4 — Serder (Event Message Container)

| Field | Value |
|---|---|
| **Concept Name** | Serder |
| **Cross-Cut Type** | Infrastructural |
| **Fan-In Count** | 6 (BC-1 event construction; BC-2 Hab event signing; BC-5 OOBI KEL parsing; BC-6 ACDC/TEL events; BC-7 EXN messages; BC-4 Baser schema cache serialization) |
| **Current Owner** | BC-3 CESR Encoding |
| **Resolution** | **Shared kernel** — Serder's cross-cut is by design: it is the domain's codec boundary between bytes and typed protocol messages. BC-3 retains ownership authority (codec implementation, SAID computation, version-string parsing). All other BCs are legitimate consumers. No ownership change is needed. The V05 leakage violation (`cbor2`/`msgpack` imported outside `serdering.py`) is an implementation hygiene issue, not a structural ownership problem. |

---

### 8.3 Delta Summary — Pass 1

| Metric | Count | Notes |
|---|---|---|
| **New concepts classified** | 69 | Full §5.2 registry across 7 BCs; includes 4 absent-type entries (Dber ABC, Signing Oracle, Digest Oracle, and Validator implied) |
| **New absences detected** | 13 | A01–A13; 4 carried forward from §5.4; 9 newly identified from §6.4 decomposition and §8.1 analysis |
| **Ownership changes** | 0 | Pass 1 establishes initial ownership; no prior assignments exist to change |
| **Reclassifications** | 0 | Pass 1 establishes initial classifications; no prior classifications exist to reclassify |
| **Isomorphism violations resolved** | 0 | 13 violations identified (V01–V13); none resolved in Pass 1 (analysis pass only) |

**Delta assessment:** Delta ≠ 0. Pass 2 is required.

Primary sources of remaining delta:
1. **14 unlisted §6.4 named-class candidates** not yet in §5 registry: `Tever`, `Parser`, `Adjudicator`, `OobiResolver`, `IpexHandler`, `Receiptor`, `Poster`, `Broker`, `Router`, `Revery`, `Configer`, `Encrypter`, `Decrypter`, `Registry`
2. **13 absence entries** with `Build` disposition requiring §5 classification (A01–A12) or architecture work (A13 deferred)
3. **Cross-cut shared-kernel declarations** (CC-1 Baser, CC-4 Serder) not yet reflected in §3.3 bounded context descriptions
4. **0 isomorphism violations resolved** — V01–V13 remain open in target architecture

---

## Section 9 — Iteration Log

### 9.1 Pass Log

| Field | Value |
|---|---|
| **Pass Number** | 1 |
| **Date / Time** | 2026-03-06T19:54:00Z |
| **Phases Completed** | 1 (Domain Identity), 2 (External Domain Catalog), 3 (Concept Registry), 4 (Composite Decomposition), 5 (File Schema), 6 (Absence and Cross-Cut Report) |
| **Key Changes** | §2: 20 ubiquitous language terms defined; §3: 7 bounded contexts with domain purpose, responsibilities, and boundaries; §4: 9 external domains catalogued, all 5 leakage checks FAIL, no port abstractions exist; §5.2: 69 concepts classified across 7 BCs; §5.3: 36 concept cards written; §5.4: 4 absent concepts recorded; §6.2: 36 composite decomposition trees, 27 unlisted concepts surfaced; §7.1: full file schema table across 8 groups; §7.2: 13 isomorphism violations (V01–V13) documented with remediation paths; §7.3: 11 ownership invariants stated; §8.1: 13 absence entries documented; §8.2: 4 cross-cut concepts identified and classified; §8.3: delta summary shows delta ≠ 0 |
| **Decisions Made** | (1) Baser classified as BC-4-owned shared kernel, cross-BC read access is by design; (2) hio Doer treated as ED-5 external constraint, not a domain concept — redirect to port abstraction deferred; (3) Escrow classified as BC-1 core concept despite split physical ownership between `eventing.py` and `basing.py`; (4) Witness and Watcher classified as BC-5 core concepts despite absence of named classes — V09/V10 violations raised; (5) All five leakage checks FAIL — keripy is a pragmatic reference implementation without hexagonal architecture; (6) `Validator` absence resolved as Defer — adequately expressed through Kevery + Adjudicator; (7) `Kever` classified as implicit cross-cut with BC-1 exclusive mutation authority |
| **Convergence Status** | **Not converged** — delta ≠ 0 |

---

### 9.2 Convergence Declaration

**CONVERGED. Delta = 0. No further passes required.**

All four required conditions are met as of Pass 3:

**Condition 1 — All §6.4 unlisted named-class candidates have §5 registry entries. ✓**
Pass 3 classified the 2 remaining named-class candidates: `Verifier` (§5.2 Pass 3) and `BaseRegistry` (§5.2 Pass 3). No new named-class candidates emerged from their decompositions. All unlisted concepts identified across all passes are either classified in §5 or explicitly designated as non-classification-candidates (data structures, trivial utilities, or external framework types).

**Condition 2 — No `[unlisted]` leaf nodes remain in any §6.2 decomposition tree. ✓**
Pass 3 decompositions of `Verifier` and `BaseRegistry` surfaced only `CacheResolver` as an unlisted child. `CacheResolver` is confirmed as a non-classification-candidate: a trivial schema SAID-to-bytes utility wrapper (`core/scheming.py`) with no domain invariants of its own. It is recorded in §6.4 Pass 3 Addendum for completeness. No further named-class candidates were surfaced.

**Condition 3 — §3.3 bounded context descriptions reflect shared-kernel declarations. ✓**
Pass 3 edited §3.3 in-place: BC-1 received the Kever shared read-only value object export declaration; BC-3 received the explicit shared kernel status statement for CESR Encoding types; BC-4 received the explicit shared kernel status statement for Baser.

**Condition 4 — §8.1 absence entries with Build disposition have confirmed code existence or explicit Defer/Descope decisions. ✓**
A01–A06 reclassified to "Defer — future architectural work" in §8.1 Pass 3 Absence Updates. All six are confirmed absent from keripy source. Each deferral is documented with justification. Domain analysis is complete for all six concepts; implementation is outside the scope of specification analysis.

**Condition 5 — Isomorphism violations tracked (optional). ✓**
V01–V13 remain open in code. No new violations emerged from any pass. All violations have documented remediation paths in §7.2. The specification analysis is stable: violation tracking is complete and no further analysis passes are needed to achieve spec convergence.

The DDD specification for keripy is now **converged**. The concept registry is complete, the concept graph is stable, bounded context boundaries are declared, shared kernel components are identified, and all absence entries have explicit disposition decisions. Remaining work is architectural implementation (V01–V13 remediation, A01–A06 build work) tracked independently of the specification.

---

*End of Phase 6 output. Pass 1 complete. Pass 2 required — see outbox trigger.*

---

## Section 5.2 — Pass 2 Additions

The following 14 concepts correspond to the named-class candidates identified in §6.4. Each class was confirmed to exist in the stated file before classification. Note: the §6.4 label "OobiResolver" maps to the actual class `Oobiery` in `app/oobiing.py`; no class named `OobiResolver` exists.

#### BC-1 — Event Processing (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Parser | core | complex | composite | dark | code-only | `core/parsing.py:29` | CESR stream ingestion boundary. Routes KEL events to Kevery, TEL to Tevery, EXN to Exchanger, RPY to Revery, credentials to Verifier. Dual-version CESR code table dispatch (1.0 and 2.0). All incoming protocol messages enter the domain through this class. |
| Router | core | non-trivial | composite | implement | code-only | `core/routing.py:21` | Reply-message (`rpy`) route dispatcher. Maintains an ordered list of (regex, resource, suffix) Route entries. `addRoute()` registers handler by URI template; `dispatch()` matches the `r` field and invokes `processReply{suffix}()` on the matched resource. |
| Revery | core | substantive | composite | implement | partial | `core/routing.py:130` | Reply event processor implementing BADA (Best Available Data Acceptance). Validates `rpy` message SAID, dispatches via Router, applies latest-signed-pairwise acceptance policy. Owns reply escrow processing for partially-signed or unverifiable rpy messages. 3600s timeout on escrow. |

---

#### BC-2 — Key Management (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Encrypter | core | non-trivial | atomic | port | code-only | `core/signing.py:750` | Matter subclass for X25519 asymmetric encryption of private key/seed material. Derives encryption public key from Ed25519 verkey via pysodium. Encrypted output is a CESR-typed Cipher primitive. Leakage: pysodium embedded directly (V06). Should be behind SigningOracle port (V12). |
| Decrypter | core | non-trivial | atomic | port | code-only | `core/signing.py:885` | Matter subclass for X25519 asymmetric decryption of cipher text back to private key/seed. Derives decryption private key from Ed25519 sigkey via pysodium. Decryption is transient; raw key bytes must be zeroed after use. Leakage: pysodium embedded directly (V06). Should be behind SigningOracle port (V12). |
| Configer | peripheral | trivial | atomic | implement | code-only | `app/configing.py:29` | Config file reader extending hio `Filer`. Supports HJSON (human-friendly) and strict JSON. Reads/writes operator configuration for AID lifecycle parameters (OOBIs, witness URLs, delegation URLs, well-known URLs). Thin adapter; no domain logic beyond file format dispatch. |

---

#### BC-4 — Persistence (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Broker | peripheral | non-trivial | composite | implement | code-only | `db/escrowing.py:21` | Collection of 6 named LMDB sub-tables for TEL Transaction State Notices (TSNs) and their escrows: daterdb (datetime stamps), serderdb (reply serders), tigerdb (indexed sigs by quadruple), cigardb (non-indexed sig couples), escrowdb (partially-signed TSN escrow by route), saiderdb (confirmed TSN SAIDs). Provides `processEscrowState()` lifecycle. |

---

#### BC-5 — Infrastructure Services (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Adjudicator | core | non-trivial | composite | dark | partial | `app/watching.py:37` | Key state adjudicator for Watcher infrastructure. For a given watched AID, compares Key State Notice (KSN) records from each enabled watcher against local Kever state. Emits four cue kinds: keyStateConsistent, keyStateLagging, keyStateUpdate, keyStateDuplicitous. Threshold (toad) governs minimum consistent-watcher count for keyStateUpdate. |
| Oobiery | core | substantive | composite | dark | partial | `app/oobiing.py:271` | OOBI resolution pipeline. Fetches URL via HTTP Clienter, parses response with a locally-constructed Parser+Kevery+Router+Revery, validates the key event stream, stores OobiRecord+EndpointRecord in Baser, emits resolution cue. 30s retry delay on failure. Note: §6.4 label "OobiResolver" maps to this class. |
| Receiptor | core | substantive | composite | dark | code-only | `app/agenting.py:27` | Controller-side witness receipt orchestration DoDoer. Two sub-Doers: `witDo` (sends KEL events to all witnesses, propagates receipts across witness pool, catches new witnesses up on rotation) and `gitDo` (queries witnesses for specific receipts by sn on demand). Differs from WitnessReceiptor: Receiptor is controller-side; WitnessReceiptor is witness-side. |

---

#### BC-6 — Verifiable Credentials / ACDC (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Tever (TEL Key State) | core | substantive | composite | dark | code-only | `vdr/eventing.py:628` | In-memory TEL state object parallel to Kever. Tracks current state of a credential registry: .prefixer, .sn, .serder, .toad, .baks, .cuts, .adds, .noBackers. Created by valid `vcp`, updated by `iss`/`rev` only after KEL anchor confirmed. Produced and managed by Tevery. |
| IpexHandler | core | substantive | composite | dark | partial | `vc/protocoling.py:25` | IPEX step dispatch handler registered with Exchanger by route path. `verify()` enforces chain-of-SAIDs invariant via PreviousRoutes mapping: each step's `p` field must reference the SAID of the immediately preceding valid step. One handler instance per IPEX route (e.g., `/ipex/grant`). |
| Registry | core | substantive | composite | dark | partial | `vdr/credentialing.py:277` | Per-registry credential lifecycle object extending BaseRegistry. Provides `make()` (creates vcp registry inception event), `rotate()` (updates backer list), `issue()` (creates and anchors iss TEL event), `revoke()` (creates rev TEL event). Assembles Hab, Reger, Tevery, Parser. Per-registry counterpart to Hab. |

---

#### BC-7 — Peer Messaging (Pass 2)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Poster | peripheral | non-trivial | composite | dark | partial | `app/forwarding.py:25` | Store-and-forward DoDoer. Wraps any KERI event (KEL, TEL, or exn peer message) in a `/fwd` `exn` envelope signed by the sender's Hab and delivers to the recipient's mailbox, agent, or controller endpoint in priority order. Used for delegation notifications and group multisig coordination messages. |

---

## Section 5.3 — Pass 2 Concept Cards

Concept cards for all 11 composite concepts classified in Pass 2, organized by bounded context.

---

#### BC-1 — Event Processing (Pass 2 Cards)

---

**Parser**
- Axes: core | complex | composite
- Parser is keripy's CESR stream ingestion boundary: it reads from an incoming message bytearray and routes each decoded message to the appropriate domain processor — Kevery for KEL events, Tevery for TEL events, Exchanger for `exn` peer messages, Revery for `rpy` reply messages, and Verifier for credential verification. Its invariant is that no domain processor receives a message that has not been decoded from a valid CESR-framed stream with attachment groups correctly attributed to the preceding message body. It assembles Counter code tables across two CESR versions (1.0 and 2.0), a method-dispatch map keyed by CESR count codes, and references to all five domain processors. The dual-version code table dispatch (class-level `Methods` dict) is the structural source of its complex classification.
- **Does NOT own:** CESR code table definitions (Counter owns those). Validation logic for any message type (Kevery, Tevery, Exchanger, Revery each own their own). Network I/O (Protocol Message Channel port owns that).

---

**Router**
- Axes: core | non-trivial | composite
- Router is the `rpy` reply-message route dispatcher. It maintains an ordered list of `Route` entries (each comprising a compiled URI template regex, matched field names, a resource handler object, and an optional method suffix). `addRoute(routeTemplate, resource, suffix)` compiles the template to a regex and appends the Route. `dispatch(serder, saider, cigars, tsgs)` extracts the `r` field, linearly searches for the first matching Route, derives the handler method name as `processReply{suffix}`, and invokes it on the resource. Its invariant is that every dispatched `rpy` message must match a registered route; unmatched routes raise `ConfigurationError` via `processRouteNotFound`.
- **Does NOT own:** Reply message validation (Revery owns BADA policy). Handler-specific reply semantics (each registered resource owns its processReply method). Message source verification (Kevery/Kever own that).

---

**Revery**
- Axes: core | substantive | composite
- Revery is the `rpy` reply event processor implementing the BADA (Best Available Data Acceptance) model. It assembles a `Router` (for route-specific dispatch), a `Baser` reference (for prior reply state comparison), and a `cues` Deck. `processReply()` verifies the message SAID and dispatches via Router. `acceptReply()` applies the latest-signed-pairwise comparison rule: a new reply is accepted over an existing one only when its timestamp is later AND (for nontransferable signers) its key state sequence number is ≥ the prior. Partially signed or unverifiable replies land in a route-keyed escrow with a 3600s timeout. Reply validation and escrow are route-specific: each resource registered in Router owns the `processReply` method that applies its BADA variant.
- **Does NOT own:** Route handler logic (each registered resource owns that). Message body semantics (Serder/SerderKERI own that). Key state lookup (Baser/Kever own that).

---

#### BC-4 — Persistence (Pass 2 Cards)

---

**Broker**
- Axes: peripheral | non-trivial | composite
- Broker is the TEL Transaction State Notice (TSN) escrow database. Under a configurable `subkey` namespace within a `Reger` instance, it assembles six named LMDB sub-tables: `daterdb` (datetime stamps by SAID), `serderdb` (reply message serders by SAID), `tigerdb` (indexed signatures by quadruple key — SAID + prefix + sn + digest), `cigardb` (non-indexed signature couples by SAID), `escrowdb` (partially-signed TSN escrows by route), and `saiderdb` (confirmed TSN SAIDs by (prefix, aid) key). `processEscrowState(typ, processReply, extype)` is the generic escrow evaluation loop. Broker is the TEL-domain counterpart to the nine KEL escrow buckets distributed across Baser and Kevery.
- **Does NOT own:** TEL event validation (Tevery owns that). KEL escrow (Baser + Kevery own that). Storage engine internals (LMDBer owns that via Reger).

---

#### BC-5 — Infrastructure Services (Pass 2 Cards)

---

**Adjudicator**
- Axes: core | non-trivial | composite
- Adjudicator performs key state adjudication for the Watcher: for a given watched AID and optional `toad` threshold, it reads the observable watcher set from `db.obvs`, fetches each watcher's most recently reported KSN from `db.ksns`, and compares it against the local `hab.kevers[watched].state()` using `diffState()`. It classifies each watcher's report as `even`, `ahead`, `behind`, or `duplicitous` (using the `States` namedtuple). It emits one of four cue kinds: `keyStateConsistent`, `keyStateLagging`, `keyStateUpdate` (when ≥ toad consistent reports exist), or `keyStateDuplicitous`. It assembles a `Habery` reference, a `Hab` reference (for local key state and watcher records), and input/output `Deck` instances.
- **Does NOT own:** The watched AID's key state (Kever owns that). Watcher query networking (WitnessInquisitor owns that). Cue consumption logic (Watcher's caller owns that).

---

**Oobiery**
- Axes: core | substantive | composite
- Oobiery is the OOBI resolution pipeline. At construction it builds a self-contained validation stack: `Router` + `Revery` + `Kevery` (lax=True, local=False) + `Parser` (framed=True). `scoobiDo()` reads OOBI resolution requests from the Habery, sends HTTP GET requests via `Clienter`, feeds responses into the local Parser, and on successful resolution stores `OobiRecord` and `EndpointRecord` in Baser and emits a cue. Failed resolutions are retried after 30 seconds (`RetryDelay`). It also registers the `/introduce` `rpy` route to handle OOBI introductions embedded in reply messages. Its invariant is that a resolution cue is emitted only after the response produces a verifiable key event stream for the stated AID.
- **Does NOT own:** HTTP transport implementation (Clienter / ED-4 owns that). KEL event validation (the locally-constructed Kevery owns that; Oobiery only constructs it). OobiRecord persistence schema (Baser owns that).

---

**Receiptor**
- Axes: core | substantive | composite
- Receiptor is the controller-side witness receipt orchestration DoDoer. It assembles a `Clienter` (HTTP), a `msgs` Deck (events to publish), a `gets` Deck (receipt queries by sn), and a `cues` Deck, and registers two sub-Doers via `doify()`: `witDo` and `gitDo`. `witDo` processes `msgs`: for each event it submits to all witnesses in `kever.wits`, collects receipts, propagates the complete receipt set back to all witnesses, and (on rotation) catches newly-added witnesses up to the current KEL state. `gitDo` processes `gets`: queries specific witnesses for receipts at a designated sequence number. Its invariant is that `receipt()` only returns when the event's receipts have been sent to and received from the full current witness pool.
- **Does NOT own:** KEL event construction (Hab/Manager own that). Witness pool definition (Kever.wits owns that). Network transport (Clienter / ED-4 owns that).

---

#### BC-6 — Verifiable Credentials / ACDC (Pass 2 Cards)

---

**Tever (TEL Key State)**
- Axes: core | substantive | composite
- Tever is the TEL equivalent of Kever: it holds the fully verified, current state of a single credential registry as assembled from TEL events (vcp → iss/rev). It tracks `.prefixer` (registry AID), `.sn` (current sequence number), `.serder` (latest TEL event), `.toad` (backer quorum threshold), `.baks` (backer AID list), `.cuts`/`.adds` (backer pool deltas), and `.noBackers` flag. Created by `Tevery` from a valid `vcp` event; updated only by valid `iss`/`rev` events after confirming the corresponding KEL anchor via `Baser`. The `.state()` method produces a `RegStateRecord` snapshot analogous to Kever's key state record. Tever is assembled from `Baser` (for KEL anchor lookup) and `Reger` (for TEL storage) references.
- **Does NOT own:** TEL event validation routing (Tevery owns that). Credential content validation (Schemer owns that). Issuer AID key state (Kever owns that).

---

**IpexHandler**
- Axes: core | substantive | composite
- IpexHandler is a route-registered Exchanger handler implementing the IPEX six-step protocol. One instance is registered per IPEX route path (e.g., `/ipex/grant`). Its `verify()` method enforces the chain-of-SAIDs invariant using the `PreviousRoutes` mapping: each step's `p` field must reference the SAID of an existing prior message, and that prior message's verb must appear in `PreviousRoutes[verb]`. A `grant` without a valid `agree` or `offer` antecedent, or an `admit` without a `grant`, is rejected. Its invariant is that no IPEX step is accepted that would create an out-of-sequence negotiation. It assembles a `Habery` reference (for cloning prior exn messages via `exchanging.cloneMessage`), a `Notifier` reference, and the `resource` route string.
- **Does NOT own:** IPEX message transport (Exchanger/EXN own that). Credential content validation (Schemer owns that). Credential storage (Regery/Registry own that).

---

**Registry**
- Axes: core | substantive | composite
- Registry is the per-registry credential lifecycle object for a locally controlled ACDC credential registry. It extends `BaseRegistry` (which owns the core assembly: Hab, Reger, Tevery, Parser, cues) with four lifecycle methods: `make()` creates and processes the `vcp` registry inception TEL event; `rotate()` produces a registry rotation TEL event updating the backer list; `issue(said)` creates and anchors an `iss` credential issuance TEL event to the issuer's KEL; `revoke(said)` creates and anchors a `rev` revocation TEL event. Its invariant is that no `iss` or `rev` event is applied before `inited == True`, and that every TEL event is anchored to the issuer's KEL via `anchorMsg()` before Tevery processes it. Registry is the per-registry counterpart to Hab, as Regery is to Habery.
- **Does NOT own:** TEL event validation (Tevery owns that). Credential content authoring (ACDC body schema). Credential presentation (IPEX owns that). Backer/witness quorum enforcement (Tever owns that at the state object level).

---

#### BC-7 — Peer Messaging (Pass 2 Cards)

---

**Poster**
- Axes: peripheral | non-trivial | composite
- Poster is the store-and-forward DoDoer for KERI messages destined for AIDs not directly reachable. `deliverDo()` reads from the `evts` Deck (each entry has: src AID, dest AID, topic, Serder, optional attachment, optional Hab). For each event, it resolves the recipient's endpoints via `hab.endsFor(recp)` and delivers to the highest-priority available endpoint in order: controller → agent → mailbox. For mailbox endpoints it calls the KERI `/fwd` forwarding route; for direct endpoints it calls the standard delivery method. Its invariant is that every forwarded message includes the original event body plus its CESR attachments and is signed by the sender's Hab keys; the `/fwd` envelope identifies both the source and destination AIDs.
- **Does NOT own:** Endpoint resolution from KEL (hab.endsFor owns that, drawing from EndpointRecords). Message content or attachment construction (the calling domain component — Anchorer, Counselor — owns that). HTTP transport (Clienter / ED-4 owns that).

---

## Section 6.4 — Pass 2 Addendum (New Unlisted Concepts)

The following concepts appeared as children in Pass 2 concept card decompositions but have no registry entry in §5.2. They are newly identified absent concepts.

| Concept | Type | Appears In | Notes |
|---|---|---|---|
| `Verifier` | unlisted | Parser (`.vry` attribute) | `vdr/verifying.py:26`; accepts and validates TEL events with credential wallet storage; assembles Reger, Tevery, Parser, and credential escrow timeouts; named class, candidate for classification |
| `BaseRegistry` | unlisted | Registry (base class) | `vdr/credentialing.py:173`; abstract base assembling core lifecycle (Hab, Reger, Tevery, Parser, cues) for Registry and any other registry subclasses; named class, candidate for classification |
| `DiffState` | unlisted | Adjudicator | `app/watching.py:24`; `@dataclass` capturing per-watcher comparison result (pre, wit, state, sn, dig); small internal data structure, not a classification candidate |
| `Route` | unlisted | Router | Named tuple/dataclass in `core/routing.py`; fields: regex, fields, resource, suffix; internal data structure of Router, not a classification candidate |

**Candidates for §5 classification in Pass 3 (named classes with non-trivial domain significance):**
`Verifier`, `BaseRegistry`

---

## Section 8.3 — Pass 2 Delta

| Metric | Count | Notes |
|---|---|---|
| **New concepts classified** | 14 | §5.2 Pass 2 additions: Tever, Parser, Adjudicator, Oobiery, IpexHandler, Receiptor, Poster, Broker, Router, Revery, Configer, Encrypter, Decrypter, Registry |
| **New absences detected** | 2 | A14 (`Verifier`, `vdr/verifying.py`), A15 (`BaseRegistry`, `vdr/credentialing.py`) — named classes from Pass 2 decomposition trees with no §5 entries |
| **Absence entries resolved** | 6 | A07 (Tever), A08 (Parser), A09 (Adjudicator), A10 (Oobiery/OobiResolver), A11 (IpexHandler), A12 (Receiptor) — all classified in §5.2 Pass 2 |
| **Ownership changes** | 0 | No prior Pass 1 assignments changed |
| **Reclassifications** | 0 | No prior Pass 1 classifications changed |
| **Isomorphism violations resolved** | 0 | Analysis pass only; V01–V13 remain open; no new violations identified from Pass 2 classifications |

**Delta assessment:** Delta ≠ 0. Pass 3 is required.

Primary sources of remaining delta after Pass 2:
1. **2 new named-class candidates** from decomposition: `Verifier`, `BaseRegistry` — need §5 classification in Pass 3
2. **A01–A06 remain open** — confirmed absent from keripy source; require explicit Build or Defer/Descope decision per convergence Condition 4
3. **§3.3 shared-kernel declarations** not yet updated — Condition 3 unmet
4. **V01–V13 remain open** — all 13 isomorphism violations unresolved in code (not required for spec convergence but tracked)

**Decisions made in Pass 2:**
- `OobiResolver` (§6.4 label) maps to `Oobiery` (actual class `app/oobiing.py:271`); no `OobiResolver` class exists
- `Encrypter` and `Decrypter` classified as `port` disposition — concrete X25519 cipher adapters that should sit behind the `SigningOracle` port abstraction (parallel to `LMDBer` classified as `port` in Pass 1)
- `Configer` classified as `atomic` — extends `hio.base.filing.Filer` with file format dispatch but does not assemble domain sub-components
- `Parser` classified as `complex` weight — dual-version CESR code table dispatch (class-level `Methods` dict across versions 1.0/2.0) plus five domain processor routing targets
- `Router` and `Revery` assigned to BC-1 — `core/routing.py` is listed as a BC-1 primary file in §3.3
- `Broker` assigned to BC-4 — `db/escrowing.py` is in the `db/` persistence layer (BC-4 primary files)
- `Poster` assigned to BC-7 — `app/forwarding.py` is a BC-7 primary file per §7.1 Group 7

---

## Section 9.1 — Pass Log (Pass 2 Entry)

| Field | Value |
|---|---|
| **Pass Number** | 2 |
| **Date / Time** | 2026-03-06T19:54:00Z |
| **Phases Completed** | Phase 3 (Concept Registry Pass 2) — classification of 14 §6.4 candidates |
| **Key Changes** | §5.2: 14 new concepts classified across BC-1 (Parser, Router, Revery), BC-2 (Encrypter, Decrypter, Configer), BC-4 (Broker), BC-5 (Adjudicator, Oobiery, Receiptor), BC-6 (Tever, IpexHandler, Registry), BC-7 (Poster); §5.3: 11 Pass 2 concept cards; §6.4 Pass 2 Addendum: 4 unlisted nodes identified, 2 named-class candidates (Verifier, BaseRegistry); §8.1: A07–A12 resolved by classification; §8.3 Pass 2 Delta recorded; §9.2 convergence declaration updated to Pass 3 required |
| **Decisions Made** | (1) OobiResolver concept maps to Oobiery class — no OobiResolver class exists; (2) Encrypter/Decrypter classified as `port` disposition (concrete cipher adapters, should be behind SigningOracle); (3) Configer atomic despite Filer inheritance; (4) Parser upgraded to `complex` weight; (5) Router and Revery assigned BC-1; (6) Broker assigned BC-4; (7) Poster assigned BC-7 |
| **Convergence Status** | **Not converged** — delta ≠ 0; Pass 3 required for Verifier, BaseRegistry classification |

---

*End of Phase 3 (Pass 2) output. Pass 3 required — see outbox trigger.*

---

## Section 5.2 — Pass 3 Additions

The following 2 concepts correspond to the named-class candidates identified in §6.4 Pass 2 Addendum. Both classes were confirmed to exist in the stated files before classification.

#### BC-6 — Verifiable Credentials / ACDC (Pass 3)

| Concept Name | Centrality | Weight | Structure | Disposition | Spec Coverage | File Owner | Notes |
|---|---|---|---|---|---|---|---|
| Verifier | core | complex | composite | dark | partial | `vdr/verifying.py:26` | ACDC credential verification pipeline. Accepts credentials via `creds` Deck; validates: TEL registry state → credential issuance state → expiry → schema conformance (via CacheResolver + Schemer) → credential chain (edge traversal). Four escrow types (MRE, MRI/MCE, MSE, PSE) each with 3600s timeout. Saves valid credentials to Reger. Emits telquery/query/proof/saved cues. Referenced as `.vry` in Parser. |
| BaseRegistry | core | substantive | composite | dark | code-only | `vdr/credentialing.py:173` | Abstract base class for all TEL credential registries. Assembles Hab (issuer identity), Reger (TEL storage), Tevery (injected tvy), Parser (injected psr), and cues Deck. Provides two foundational methods: `processEvent(serder)` routes TEL events to Tevery with MissingAnchorError tolerance; `anchorMsg(pre, regd, seqner, saider)` writes the TEL-to-KEL anchor into `Reger.ancs`. Extended by `Registry` (full lifecycle) and `SignifyRegistry` (Signify client lifecycle). Not formally declared as `ABC` but serves as the intended base. |

---

## Section 5.3 — Pass 3 Concept Cards

---

#### BC-6 — Verifiable Credentials / ACDC (Pass 3 Cards)

---

**Verifier**
- Axes: core | complex | composite
- Verifier is keripy's ACDC credential verification pipeline and the terminal validation boundary for all credentials entering the domain. It assembles a `Reger` (TEL state and credential storage), a `Tevery` (TEL event processor), a `Parser` (framed, wired to both Habery's Kevery and Verifier's own Tevery), a `CacheResolver` (schema SAID-to-bytes lookup from Baser cache), and a `Schemer` (applied transiently per credential). `processCredential()` runs five sequential validation stages: (1) TEL registry state present in `tevers`, (2) credential issuance state not absent or expired, (3) credential body schema conformance via Schemer, (4) each ACDC edge (`e` field node) is a verifiably issued, non-revoked, non-expired chain credential, (5) `saveCredential()` writes to Reger on full pass. Failed stages route to named escrow sub-tables in Reger (`mre`, `mce`, `mse`) with 3600s timeouts, emitting cue requests (`telquery`, `query`, `proof`) to trigger retrieval of missing data. Its invariant is that `saveCredential()` is only called after all five validation stages pass; no partial save occurs.
- **Does NOT own:** TEL event validation logic (Tevery owns that). Issuer AID key state (Kever / Habery's Kevery owns that). Schema document fetching (CacheResolver reads from Baser only; schema fetch is triggered by cue and handled by Oobiery). Credential content authoring (Registry/BaseRegistry own that). IPEX exchange protocol (IpexHandler owns that).

---

**BaseRegistry**
- Axes: core | substantive | composite
- BaseRegistry is the assembly base for all TEL credential registry implementations. It assembles `Hab` (issuer identity and signing authority), `Reger` (TEL storage), an injected `Tevery` (`tvy`), an injected `Parser` (`psr`), and a `cues` Deck. It provides the invariant-enforcing entry points that subclasses call: `processEvent(serder)` routes a TEL event to `Tevery.processEvent()` with `MissingAnchorError` caught and logged (the caller must retry when the KEL anchor arrives); `anchorMsg(pre, regd, seqner, saider)` writes a `(Number, Diger)` pair to `Reger.ancs[dgKey(pre, regd)]` to record the TEL event's anchoring KEL sequence number and digest. Its invariant is that no TEL event takes effect without a corresponding anchor in the issuer's KEL, enforced by `processEvent()`'s anchor-check in Tevery. `Registry` subclass adds `make()`, `rotate()`, `issue()`, `revoke()` for controller-owned lifecycle. `SignifyRegistry` subclass provides externally-produced event variants for Signify clients.
- **Does NOT own:** TEL event construction (subclasses' `make()`, `issue()`, `revoke()` own that). Registry loading and discovery (Regery owns that). TEL event validation logic (Tevery owns that). Issuer key signing (Hab/Manager own that).

---

## Section 6.4 — Pass 3 Addendum (New Unlisted Concepts)

The following concepts appeared as children in Pass 3 concept card decompositions but have no §5.2 registry entry. None are named-class classification candidates.

| Concept | Type | Appears In | Notes |
|---|---|---|---|
| `CacheResolver` | unlisted | Verifier | `core/scheming.py:20`; reads schema SAID → raw bytes from Baser schema cache; trivial one-method utility wrapper, no domain invariants; NOT a classification candidate |
| Credential escrow sub-tables (mre, mce, mse) | unlisted | Verifier | LMDB IoSet sub-tables in `Reger` for missing-registry, missing-chain, missing-schema escrows; infrastructure detail of Reger, not independently classifiable |

**Named-class candidates for §5 classification in a subsequent pass:** None. Delta = 0.

---

## Section 8.1 — Pass 3 Absence Updates

The following 6 absence entries remain unbuilt in the keripy codebase as of Pass 3. Each is explicitly reclassified from "Build" to "Defer" with documented justification. Domain analysis is complete for all six; implementation is deferred to future architectural work sprints.

---

#### A01 — Dber ABC — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms `class Dber` does not exist in `db/dbing.py` or anywhere in the keripy source. The architectural work is well-specified in §7.2 V02: add `class Dber(ABC)` to `db/dbing.py`, have `LMDBer` implement it, update `Baser`/`Keeper`/`Reger` base declarations. The spec analysis is complete — the port concept, its consumers, and its remediation path are all documented. Implementation requires a coordinated multi-file refactor; it is not required for specification completeness. Defer to an architecture-remediation sprint tracking V02. |

---

#### A02 — SigningOracle Port — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms no `SigningOracle` ABC or `Protocol` class exists anywhere in the keripy source. The architectural work is well-specified in §7.2 V12: create `core/ports.py` with `SigningOracle` ABC; implement `PysodiumSigningAdapter` and `CryptographySigningAdapter`; wire into `Verfer`, `Salter`, `Encrypter`, `Decrypter`. This is the highest-effort single change in the violation inventory and is prerequisite to V03/V06/V07. Spec analysis is complete. Defer to an architecture-remediation sprint tracking V12. |

---

#### A03 — DigestOracle Port — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms no `DigestOracle` ABC or `Protocol` class exists. The architectural work is specified in §7.2 V13: add `DigestOracle` ABC to `core/ports.py`; implement `Blake3DigestAdapter` and `HashlibDigestAdapter`; wire into `Diger`. Spec analysis is complete. Defer to an architecture-remediation sprint tracking V13. |

---

#### A04 — Witness (Named Class) — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms no class named `Witness` or `WitnessNode` exists in `app/indirecting.py` or anywhere in the keripy source. The concept is functionally present: `WitnessStart` in `app/indirecting.py:146` assembles the four Doers that constitute the Witness. The naming fix is low-effort (rename or thin wrapper) and fully specified in §7.2 V09. Spec analysis is complete. Defer to a naming-refactor sprint tracking V09. |

---

#### A05 — Watcher (Named Class) — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms no class named `Watcher` or `WatcherDoer` exists in `app/watching.py` or anywhere in the keripy source. The concept is functionally present: `Adjudicator` + `WitnessInquisitor` + `Kevery` constitute the Watcher assembly. The naming fix is low-effort and fully specified in §7.2 V10. Spec analysis is complete. Defer to a naming-refactor sprint tracking V10. |

---

#### A06 — KelEscrowManager — Reclassified: Defer

| Field | Value |
|---|---|
| **Prior Disposition** | Build |
| **Pass 3 Decision** | **Defer** |
| **Justification** | A code search confirms no class named `KelEscrowManager` or equivalent exists. The KEL Escrow concept is functionally present but fragmented: nine `processEscrow*` methods and timeout constants reside in `Kevery` (`core/eventing.py`) while the nine sub-table definitions reside in `Baser` (`db/basing.py`). The mediation class is medium-effort and fully specified in §7.2 V08. Spec analysis is complete — the concept, its fragmentation, and its remediation are documented. Defer to an architecture-remediation sprint tracking V08. |

---

## Section 8.3 — Pass 3 Delta

| Metric | Count | Notes |
|---|---|---|
| **New concepts classified** | 2 | §5.2 Pass 3 additions: Verifier (BC-6), BaseRegistry (BC-6) |
| **New absences detected** | 0 | No new named-class candidates emerged from Pass 3 decompositions; CacheResolver designated non-classification-candidate |
| **Absence entries resolved** | 6 | A01–A06 reclassified from "Build" to "Defer" with documented justification |
| **Ownership changes** | 0 | No prior assignments changed |
| **Reclassifications** | 0 | No prior concept classifications changed |
| **Isomorphism violations resolved** | 0 | Analysis pass only; V01–V13 remain open; no new violations identified |

**Delta assessment:** Delta = 0. Convergence reached.

All §6.4 unlisted named-class candidates have §5 entries. No new unlisted nodes without classification designations remain. §3.3 shared-kernel declarations added. A01–A06 explicitly deferred. Concept registry is complete and stable.

---

## Section 9.1 — Pass Log (Pass 3 Entry)

| Field | Value |
|---|---|
| **Pass Number** | 3 |
| **Date / Time** | 2026-03-06T19:54:00Z |
| **Phases Completed** | Phase 3 (Concept Registry Pass 3) — classification of 2 §6.4 Pass 2 candidates; §3.3 targeted edits; A01–A06 deferral decisions |
| **Key Changes** | §5.2: 2 new concepts classified: Verifier (BC-6, core/complex/composite/dark/partial) and BaseRegistry (BC-6, core/substantive/composite/dark/code-only); §5.3: 2 Pass 3 concept cards; §6.4 Pass 3 Addendum: CacheResolver recorded as non-candidate unlisted node; §3.3: BC-1 Kever shared-kernel export added; BC-3 shared kernel status declared; BC-4 shared kernel status declared; §8.1 Pass 3: A01–A06 reclassified to Defer with justification; §8.3 Pass 3 Delta: delta = 0; §9.2: convergence declared |
| **Decisions Made** | (1) Verifier classified as `complex` weight — five-stage validation pipeline with four escrow types constitutes complex assembly; (2) BaseRegistry classified as `substantive` weight — assembly base with two foundational methods but no full protocol orchestration; (3) CacheResolver designated non-classification-candidate — trivial utility wrapper with no domain invariants; (4) SignifyRegistry (BaseRegistry subclass) not surfaced as unlisted node — it is a sibling subclass, not a decomposition child of BaseRegistry; (5) A01–A06 all deferred — confirmed absent, specs complete, implementation deferred; (6) Convergence declared — all four conditions met |
| **Convergence Status** | **CONVERGED** — delta = 0; specification analysis complete |

---

*End of Phase 3 (Pass 3) output. Specification converged — no further passes required.*
