# Witness Receipt Dissemination

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Define how witness receipts are created, exchanged between witnesses, and delivered to controllers and validators.
**Normative basis:** KERI Specification, CESR Specification
**Cross-checked against:** keripy reference implementation

---

This document specifies the receipt creation, dissemination, and collection
mechanisms that support witness agreement (KAWA) and event verification. It
covers the full receipt lifecycle: from witness signature creation through
propagation to all witnesses and availability for validators.

---

## 1. Purpose and Scope

Receipt dissemination is the transport mechanism for KAWA. While KAWA defines
the agreement properties (see [witness-kawa.md](witness-kawa.md)), this
document defines how receipts physically move between participants.

**What this spec covers:**
- Receipt message structure and creation
- Dissemination strategies (round-robin and gossip)
- Controller-mediated receipt propagation
- Validator receipt collection
- Receipt attachment formats in CESR

**What this spec does NOT cover:**
- Agreement semantics and immunity proofs (see [witness-kawa.md](witness-kawa.md))
- TOAD validation rules (see [KEL Core](kel-core.md) Section 15)
- Receipt event schema (see [KEL Core](kel-core.md) Section 3.6)

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Receipt** | A signed acknowledgment of a key event by a witness or other endorser. Encoded as an `rct` event with attached signatures. |
| **Witness Indexed Signature** | A `Siger` instance whose index maps to a position in the event's witness list. Used in `-B` counter groups. |
| **Non-Transferable Receipt Couple** | A `(Prefixer, Cigar)` pair: the receiptor's non-transferable prefix and its unindexed signature. Used in `-C` counter groups. |
| **Transferable Receipt Quadruple** | A `(Prefixer, Number, Diger, Siger)` tuple: receiptor AID, latest establishment event sn, digest, and indexed signature. Used in `-D` counter groups. |
| **Round-Robin** | A dissemination strategy where the controller sequentially sends each witness's receipt to all other witnesses. |
| **Gossip** | A dissemination strategy where witnesses forward receipts to each other directly. |
| **Receipt Propagation** | The process of distributing collected receipts from individual witnesses to the full witness set. |

---

## 3. Receipt Creation

### 3.1 What a Witness Signs

When a witness accepts an event (per the first-seen policy), it signs the
**serialized event bytes** -- not a receipt-specific structure. The receipt
message itself identifies the receipted event by `(i, s, d)` but the
signature covers the original event serialization.

```
witness_receipt = sign(event_serialization, witness_private_key)
```

The signature verification at the receiver side:

```
cigar.verfer.verify(cigar.raw, lserder.raw)
```

Reference: `src/keri/core/eventing.py:4222` -- verification is against
`lserder.raw` (the stored event serialization), not the receipt message.

### 3.2 Receipt Message Structure

A receipt is created via `eventing.receipt()`:

```python
receipt(pre, sn, said, *, version, kind) -> SerderKERI
```

This produces an `rct` event with fields:

| Field | Value |
|-------|-------|
| `v` | Version string |
| `t` | `"rct"` |
| `d` | SAID of the receipted event (NOT a self-computed digest) |
| `i` | AID prefix of the receipted event |
| `s` | Sequence number of the receipted event |

Reference: `src/keri/core/eventing.py:989-1008`

The receipt message carries no key state. It is purely a reference to the
receipted event. Signatures are attached separately in CESR attachment
groups.

### 3.3 Witness Promotion

When a receipt arrives as a non-transferable couple `(Prefixer, Cigar)`, the
processor checks whether the receiptor's prefix is in the current witness
list. If it is, the receipt is **promoted** to an indexed witness signature:

```python
if rpre in wits:
    index = wits.index(rpre)
    wiger = Siger(raw=cigar.raw, index=index, verfer=cigar.verfer)
    self.db.wigs.add(keys=dgkey, val=wiger)
else:
    self.db.rcts.add(keys=dgkey, val=(cigar.verfer, cigar))
```

Reference: `src/keri/core/eventing.py:4224-4231`

This promotion allows efficient storage and threshold checking: witness
receipts are indexed by position, enabling quick determination of which
witnesses have receipted.

---

## 4. Receipt Dissemination Strategies

The KERI specification allows two dissemination strategies. The keripy
reference implementation uses round-robin (controller-mediated propagation).

### 4.1 Round-Robin Protocol

In round-robin, the controller acts as the central coordinator:

```
Phase 1: Publish event to all witnesses (N messages)
  Controller --[event]--> Witness_1
  Controller --[event]--> Witness_2
  ...
  Controller --[event]--> Witness_N

Phase 2: Collect receipts from all witnesses (N messages)
  Witness_1 --[receipt_1]--> Controller
  Witness_2 --[receipt_2]--> Controller
  ...
  Witness_N --[receipt_N]--> Controller

Phase 3: Propagate receipts to all witnesses (N messages, each containing N-1 receipts)
  Controller --[receipt_2..N]--> Witness_1
  Controller --[receipt_1,3..N]--> Witness_2
  ...
  Controller --[receipt_1..N-1]--> Witness_N
```

**Message complexity:** O(2N) for phases 1+2, plus O(N) for phase 3 = O(3N)
total messages from the controller's perspective.

**Bandwidth:** Each phase-3 message carries N-1 receipt signatures.

**Latency:** Higher than gossip because the controller must collect all
receipts before propagating.

### 4.2 Gossip Protocol

In gossip, witnesses forward receipts directly to each other:

```
Phase 1: Controller publishes event to all witnesses (N messages)
  Controller --[event]--> Witness_1
  Controller --[event]--> Witness_2
  ...

Phase 2: Each witness gossips its receipt to other witnesses
  Witness_1 --[receipt_1]--> Witness_2, Witness_3, ...
  Witness_2 --[receipt_2]--> Witness_1, Witness_3, ...
  ...
```

**Message complexity:** O(N * log(N)) with optimized gossip, O(N^2) with
naive all-to-all.

**Bandwidth:** Higher than round-robin due to redundant receipt delivery.

**Latency:** Lower than round-robin because witnesses begin forwarding
immediately upon receipt, without waiting for the controller to collect all
receipts.

### 4.3 Trade-offs

| Aspect | Round-Robin | Gossip |
|--------|------------|--------|
| **Message count** | O(3N) | O(N * log(N)) to O(N^2) |
| **Bandwidth** | Lower (no redundancy) | Higher (redundant delivery) |
| **Latency** | Higher (serial collection) | Lower (parallel forwarding) |
| **Controller dependency** | Controller must be online for propagation | Witnesses operate independently after initial publish |
| **Implementation complexity** | Simple | Requires peer-to-peer witness connectivity |
| **keripy implementation** | Yes (`Receiptor`, `WitnessReceiptor`) | No |

---

## 5. Controller Receipt Flow

The keripy implementation uses controller-mediated round-robin propagation.
The flow is orchestrated by two classes.

### 5.1 Receiptor (Synchronous HTTP)

`Receiptor` uses synchronous HTTP request/response to collect and propagate
receipts.

```
1. Controller sends event to /receipts endpoint on each witness
2. Witness returns receipt in HTTP response body
3. Controller parses receipt response, strips count code
4. Controller constructs propagation message for each witness:
   a. Optionally prepend witness endpoint schemes (for icp/dip or new witnesses)
   b. Append receipt serder
   c. Append NonTransReceiptCouples counter + signatures from other witnesses
5. Controller sends propagation messages to each witness
```

Reference: `src/keri/app/agenting.py:57-156`

Key implementation detail: the controller sends each witness the complement
of all OTHER witnesses' receipts (line 129):

```python
ewits = [w for w in rcts if w != wit]  # complement
wigers = [rcts[w] for w in ewits]       # their signatures
```

### 5.2 WitnessReceiptor (Asynchronous Messenger)

`WitnessReceiptor` uses asynchronous messengers (`HTTPMessenger` or
`TCPMessenger`) for more robust receipt handling.

```
1. Check if full receipt complement already exists (db.wigs)
2. If not complete:
   a. Send delegation chain to each witness
   b. For icp/dip or new witnesses: send full KEL via clonePreIter
   c. Send event message to each witness
   d. Wait until db.wigs has N entries (all witnesses receipted)
3. Construct receipt messages with indexed witness signatures:
   a. For each witness, collect signatures from all OTHER witnesses
   b. Wrap in receipt serder via eventing.messagize()
   c. Send via messenger
4. Wait for all messengers to go idle
```

Reference: `src/keri/app/agenting.py:287-442`

### 5.3 New Witness Catch-Up

When a rotation event adds new witnesses (`ba` field), those witnesses need
the full KEL history before they can receipt the rotation event. The
controller handles this by sending a clone of the entire KEL:

```python
for fmsg in hab.db.clonePreIter(pre=pre):
    witer.msgs.append(bytearray(fmsg))
```

Endpoint scheme information (OOBIs) for existing witnesses is also sent so
the new witness can discover its peers.

Reference: `src/keri/app/agenting.py:375-378`

---

## 6. Validator Receipt Collection

Validators consume receipts independently of the KAWA protocol. They do not
participate in receipt propagation but verify that collected receipts meet
their TOAD requirement.

### 6.1 Independent Collection

A validator can collect receipts from any witness directly using
`WitnessInquisitor`. This class sends KEL query messages to witnesses and
processes the responses:

```python
WitnessInquisitor.query(pre, r="logs", sn='0', fn='0', ...)
```

The validator selects a random witness and sends a `qry` message. The
response contains the event with attached receipt signatures.

Reference: `src/keri/app/agenting.py:445-602`

### 6.2 Ambient Verifiability

Validators verify witness signatures without contacting witnesses directly.
Because witness identifiers are non-transferable, a validator can verify a
witness receipt using only:
- The witness's public key (derived from its non-transferable AID prefix)
- The receipted event serialization
- The receipt signature

No live network access to the witness is required for verification. This
property is called **ambient verifiability**.

### 6.3 Validator TOAD Independence

The validator's TOAD may differ from the controller's TOAD. The controller
sets `bt` in establishment events, but a validator MAY apply a stricter
threshold. The validator counts verified witness receipts and checks:

```
len(verified_witness_receipts) >= validator_toad
```

---

## 7. Receipt Attachment Formats

Receipts are attached to CESR protocol streams using counter codes that
frame the signature groups.

### 7.1 Witness Indexed Signatures (`-B` counter, v1.0)

Used when the receiptor is a known witness in the event's witness list. Each
signature is a `Siger` instance indexed by position in the witness list.

```
-B[count]  Siger_0  Siger_1  ...  Siger_{count-1}
```

The index in each `Siger` maps directly to the witness list position at the
time of the receipted establishment event.

### 7.2 Non-Transferable Receipt Couples (`-C` counter, v1.0)

Used for receipts from non-transferable identifiers that may or may not be
witnesses. Each couple is a `(Prefixer, Cigar)` pair.

```
-C[count]  (Prefixer_0, Cigar_0)  (Prefixer_1, Cigar_1)  ...
```

When processed, witness couples are promoted to indexed signatures and stored
in `db.wigs`. Non-witness couples are stored in `db.rcts`.

### 7.3 Transferable Receipt Quadruples (`-D` counter, v1.0)

Used for receipts from transferable identifiers (typically watchers, not
witnesses). Each quadruple contains the receiptor's AID, its latest
establishment event reference, and an indexed signature.

```
-D[count]  (Prefixer_0, Seqner_0, Diger_0, Siger_0)  ...
```

### 7.4 Counter Code Versions

| Counter (v1.0) | Counter (v2.0) | Type |
|----------------|----------------|------|
| `-A` | (reassigned) | Controller indexed signatures |
| `-B` | (reassigned) | Witness indexed signatures |
| `-C` | (reassigned) | Non-transferable receipt couples |
| `-D` | (reassigned) | Transferable receipt quadruples |

In CESR v2.0, the `-A`/`-B`/`-C`/`-D` codes are reassigned to generic group
types. See the CESR specification and `src/keri/core/counting.py` for the
complete counter code mapping.

---

## 8. Implementation Notes

### 8.1 Receipt Processing Pipeline

The `Kevery.processReceipt()` method at `src/keri/core/eventing.py:4155`
handles all three receipt types (cigars, wigers, transferable sig groups):

```
processReceipt(serder, cigars, wigers, tsgs, local):
  1. Look up the last-seen event at (pre, sn) via db.kels.getOnLast()
  2. Verify the receipt's SAID matches the stored event's SAID
     (reject stale receipts where SAID does not match)
  3. For each cigar (non-transferable couple):
     a. Skip transferable verfers
     b. Skip own receipts on own events (unless local)
     c. Verify signature against stored event serialization
     d. If receiptor prefix is in witness list: promote to indexed wiger
     e. Else: store as non-witness receipt
  4. For each wiger (witness indexed signature):
     a. Assign verfer from witness list by index
     b. Skip transferable verfers
     c. Skip own receipts (unless local)
     d. Verify signature against stored event serialization
     e. Store in db.wigs
  5. For each transferable sig group:
     a. Look up receiptor's establishment event
     b. Verify receiptor's signatures against its own key state
     c. Store in appropriate receipt database
```

### 8.2 Stale Receipt Handling

A receipt is stale when the SAID in the receipt does not match the SAID of the
currently stored event at that (prefix, sequence number). This can occur when
a superseding rotation has replaced the event at that sequence number. Stale
receipts are rejected with `ValidationError`.

Reference: `src/keri/core/eventing.py:4199-4201`

### 8.3 keripy Receipt Classes Summary

| Class | File:Line | Purpose |
|-------|-----------|---------|
| `Receiptor` | `agenting.py:29` | Synchronous HTTP receipt collection and propagation |
| `WitnessReceiptor` | `agenting.py:287` | Asynchronous receipt cycle with full KEL catch-up |
| `WitnessInquisitor` | `agenting.py:445` | Query witnesses for KEL/TEL events and receipts |
| `WitnessPublisher` | `agenting.py:605` | Send outbound CESR messages to all witnesses |
| `HTTPMessenger` | `agenting.py` | HTTP transport for witness communication |
| `TCPMessenger` | `agenting.py:691` | TCP transport for witness communication |

### 8.4 Receipt Propagation Message Format

The propagation message sent by the controller to each witness contains:

```
[endpoint schemes (optional)]    -- OOBI info for new witnesses
[receipt serder]                 -- rct event identifying the receipted event
[counter code]                   -- NonTransReceiptCouples or WitnessIdxSigs
[signatures]                     -- receipt signatures from other witnesses
```

For `Receiptor` (synchronous), non-transferable receipt couples (`-C`) are
used. For `WitnessReceiptor` (asynchronous), witness indexed signatures
(`-B`) are used via `eventing.messagize()`.
