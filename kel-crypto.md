# KEL Crypto: Foundations and Signature Verification

**Version:** 0.1.1-draft
**Status:** Draft
**Part of:** [KEL Specification](kel-specification.md)
**Dependencies:** CESR specification, KERI specification (external)
**Interface exported:** `Primitives` — crypto operations consumed by all higher layers

---

This document defines the cryptographic primitive types, serialization formats,
content-addressing mechanism, and signature verification model that all higher
layers build upon. An implementation of this layer (e.g., cesride in Rust,
cesr-ts in TypeScript) can be used independently of the rest of the KEL stack.

---

## 1. Cryptographic Primitive Types

All primitives use CESR (Composable Event Streaming Representation) encoding: a
type code prefix followed by the raw cryptographic material, yielding a
self-describing, fixed-length, base64-safe qualified string.

### Verfer (Public Key Verifier)

Wraps a public key with algorithm-agile signature verification.

```
Verfer
  .code         -- CESR derivation code identifying cipher suite
  .raw          -- unqualified public key bytes
  .qb64         -- fully qualified CESR string (code + base64 material)
  .verify(sig, ser) → bool
                -- returns true if signature sig verifies on serialization ser
```

**Supported cipher suites:**

| Code prefix | Algorithm | Key size |
|-------------|-----------|----------|
| `B` | Ed25519 (non-transferable) | 32 bytes |
| `D` | Ed25519 (transferable) | 32 bytes |
| `1AAB` | ECDSA secp256r1 (non-transferable) | 33 bytes |
| `1AAC` | ECDSA secp256r1 (transferable) | 33 bytes |
| `1AAD` | ECDSA secp256k1 (non-transferable) | 33 bytes |
| `1AAE` | ECDSA secp256k1 (transferable) | 33 bytes |

Non-transferable codes (`B`, `1AAB`, `1AAD`) indicate the key cannot participate
in rotation — used for witnesses and other infrastructure identifiers.

### Diger (Digest Verifier)

Wraps a hash digest with algorithm-agile verification and comparison.

```
Diger
  .code         -- CESR code identifying hash algorithm
  .raw          -- unqualified digest bytes
  .qb64         -- fully qualified CESR string

  .verify(ser) → bool
                -- returns true if digest of ser matches .raw

  .compare(ser, dig=None, diger=None) → bool
                -- algorithm-agile comparison: recomputes digests using
                -- both algorithms to verify both are valid digests of ser
```

**Supported algorithms:**

| Code prefix | Algorithm | Digest size |
|-------------|-----------|-------------|
| `E` | Blake3-256 | 32 bytes |
| `F` | Blake2b-256 | 32 bytes |
| `G` | Blake2s-256 | 32 bytes |
| `H` | SHA3-256 | 32 bytes |
| `I` | SHA2-256 | 32 bytes |
| `0D` | Blake3-512 | 64 bytes |
| `0E` | Blake2b-512 | 64 bytes |
| `0F` | SHA3-512 | 64 bytes |
| `0G` | SHA2-512 | 64 bytes |

**Blake3-256 (`E` prefix) is the default digest algorithm for SAID computation
in KERI events.**

### Prefixer (Identifier Prefix)

An AID prefix — a qualified CESR primitive. For self-addressing identifiers,
the prefix IS the SAID of the inception event: the identifier is derived from
(and bound to) its own inception.

```
Prefixer
  .code         -- CESR code, must be a valid AID prefix code
  .raw          -- prefix material (digest of inception event for self-addressing)
  .qb64         -- fully qualified AID string
  .transferable -- true if code indicates transferable key type
```

### Number (Sequence/Ordinal Numbers)

Represents non-negative integers for sequence numbers, first-seen ordinals,
and thresholds.

```
Number
  .code         -- CESR code sized to fit value (Short, Tall, Big, etc.)
  .raw          -- big-endian unsigned bytes
  .num          -- integer value
  .numh         -- hexadecimal string (no leading zeros)
  .sn           -- alias for .num (sequence number context)
  .snh          -- alias for .numh
  .positive     -- true if .num > 0
  .inceptive    -- true if .num == 0
```

**Code sizing:** Automatically selects the smallest CESR code that fits the
value:

| Code | Name | Max value |
|------|------|-----------|
| Short | 2-byte | 65,535 |
| Tall | 5-byte | ~1.1 × 10^12 |
| Big | 8-byte | ~1.8 × 10^19 |
| Large | 11-byte | ~5.2 × 10^26 |
| Great | 14-byte | ~1.5 × 10^33 |
| Vast | 17-byte | ~4.3 × 10^40 |

---

## 2. Threshold Representation

Thresholds control how many signatures (and which ones) must verify for an
event to be accepted. KERI supports both simple numeric thresholds and weighted
fractional thresholds.

### Tholder (Threshold Holder)

```
Tholder
  .weighted     -- true for fractional weighted, false for numeric M-of-N
  .thold        -- parsed threshold (int for numeric, nested list of Fractions for weighted)
  .sith         -- serializable form for JSON/CBOR/MGPK
  .limen        -- CESR-encoded form (Number.qb64b or Bexter.qb64b)
  .size          -- minimum key list size this threshold requires
  .num          -- for numeric: the M value; for weighted: None

  .satisfy(indices) → bool
                -- returns true if the list of verified signature indices
                -- satisfies the threshold
```

**Numeric threshold (M-of-N):**

`sith = "2"` means: at least 2 out of N keys must sign. Serialized as a hex
string. The `satisfy` algorithm simply checks `len(verified_indices) >= M`.

**Weighted fractional threshold:**

`sith = [["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]`

This represents AND-clauses of OR-weighted keys. Each clause must independently
sum to >= 1 from verified signatures:
- Clause 1: Keys 0-4 with weights 1/2, 1/2, 1/4, 1/4, 1/4. Any combination
  summing >= 1.
- Clause 2: Keys 5-6 with weights 1, 1. Both must sign (each is weight 1).

**Weighted satisfy algorithm:**
1. Remove duplicate indices and sort ascending
2. Create boolean array `sats[0..size-1]`, set `sats[i] = true` for each
   verified index
3. wio = 0   (weight index offset -- advances through sats array)
   For each clause (AND):
     clause_weight = 0
     For each element in the clause:
       - If bare weight (Fraction):
           if sats[wio]: clause_weight += weight
           wio += 1
       - If keyed weight (Fraction, [Fraction, ...]):
           value_weight = 0
           for each w in value_weights:
               if sats[wio]: value_weight += w
               wio += 1
           if value_weight >= 1: clause_weight += key_weight
     - If clause_weight < 1: return false
4. All clauses satisfied: return true

Source: `src/keri/core/coring.py` lines 4805-4851, variable `wio`

**Keyed (nested) weights:**

Elements in a clause may be keyed weight groups — a single key weight
governing a sub-group of value weights. JSON representation uses a
single-entry map:

```
sith = [{"1/3": ["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]
```

This is a single AND-clause with 4 elements spanning 7 key positions:
- Positions 0-2: keyed group `{"1/3": ["1/2", "1/2", "1/2"]}` — the three
  value weights (1/2 each) are summed for verified positions. If the sum >= 1,
  the key weight (1/3) is contributed to the clause.
- Position 3: bare weight `"1/3"`
- Position 4: bare weight `"1/2"`
- Positions 5-6: keyed group `{"1/2": ["1", "1"]}` — both value weights are 1,
  so both must sign. If satisfied, contributes 1/2 to the clause.

Internally, keyed weights are parsed as tuples: `(Fraction, [Fraction, ...])`.

**CESR encoding of weighted thresholds:** The `.limen` property encodes
weighted thresholds as a Bexter (variable-length Base64 text primitive from
CESR). Fraction delimiters: `s` = slash, `c` = comma between elements,
`a` = AND between clauses, `k` = separates key weight from nested values,
`v` = separates nested value weights.

Examples:
- `[["1/2", "1/2"], ["1"]]` → bext `1s2c1s2a1`
- `[{"1/3": ["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]` →
  bext `1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1`

For numeric thresholds, `.limen` encodes as a Number (CESR integer primitive)
instead.

**Default threshold:** When not specified, implementations SHOULD default to
majority: `ceil(len(keys) / 2)`.

---

## 3. Serialization Formats

KERI events can be serialized in four formats:

| Kind code | Format | Notes |
|-----------|--------|-------|
| `JSON` | JSON field map | Text, human-readable |
| `CBOR` | CBOR binary field map | RFC 8949 |
| `MGPK` | MessagePack binary field map | Compact binary |
| `CESR` | Native CESR encoding | Version 2.0+ only |

All formats preserve field ordering. The serialization format is encoded in
the version string.

---

## 4. Version String Structure

Every KERI event begins with a version string in the `v` field that identifies
the protocol, version, serialization format, and message size.

**Version 1.0 format** (17 characters):

```
KERI10JSON00012c_
^^^^  ^^^^  ^^^^^^ ^
|  |  |     |      terminator: underscore
|  |  |     size: 6 hex digits (serialized message size in bytes)
|  |  kind: 4 chars (JSON, CBOR, MGPK)
|  version: 1 hex digit major, 1 hex digit minor
protocol: 4 chars
```

**Version 2.0 format** (19 characters):

```
KERI2A2A02JSON0001.
^^^^        ^^^^    ^
|  |  |  |  |  |    terminator: dot
|  |  |  |  |  size: 4 Base64 chars
|  |  |  |  kind: 4 chars (JSON, CBOR, MGPK, CESR)
|  |  |  CESR genus version: 1 Base64 major, 2 Base64 minor
|  |  protocol version: 1 Base64 major, 2 Base64 minor
protocol: 4 chars
```

---

## 5. Content Addressing (SAID Computation)

A SAID (Self-Addressing Identifier) is a digest embedded within the data
structure it digests. This creates a cryptographic binding between the
identifier and the content.

**SAID computation algorithm:**

1. **Dummy replacement:** Replace each SAID field with `#` characters sized
   to the target digest's CESR full-size
2. **Size calculation:** Serialize with dummies to compute message size
3. **Version string update:** Recompute the version string with the correct
   size
4. **Digest computation:** Serialize again with updated version string,
   compute Blake3-256 digest
5. **SAID insertion:** Replace dummy with the computed digest (CESR qb64)
6. **Final serialization:** Serialize once more with the actual SAID values

**Digest chain invariant:** Every non-inception event contains a `p` (prior)
field holding the SAID of its predecessor. This creates a hash chain: any
modification to a prior event invalidates all subsequent SAIDs.

For inception events, the `i` (identifier) field is ALSO a SAID — the AID
prefix is derived from the inception event content. Both `d` and `i` fields
are computed as SAIDs using Blake3-256.

---

## 6. Indexed Signature Model (Siger)

A Siger carries a cryptographic signature along with an index into a key list,
enabling multi-key threshold verification.

```
Siger
  .code         -- CESR code identifying cipher suite and index mode
  .raw          -- signature bytes
  .index        -- offset into the current signing key list
  .ondex        -- offset into the prior next-key list (or None)
  .verfer       -- associated Verfer (assigned during verification)
  .qb64         -- fully qualified CESR string
```

**Signature code categories:**

| Category | Example codes | Has ondex | Use case |
|----------|--------------|-----------|----------|
| Full index (`_Sig`) | `A` (Ed25519) | Yes | Rotation events: maps between current and prior-next key lists |
| Current-only (`_Crt_Sig`) | `B` (Ed25519) | No (None) | Inception and interaction events: only current key list |
| Big variants | `2A`, `2B` | Yes/No | Large index values (> 63) |

---

## 7. Dual-Index Mechanism (ondex)

During key rotation, signers must prove they control keys that were
pre-committed in the prior establishment event's next-key digest list.
The dual-index mechanism enables this:

- **`.index`**: Offset into the CURRENT signing key list (`k` field of this
  event)
- **`.ondex`**: Offset into the PRIOR next-key digest list (`n` field of the
  prior establishment event)

When verifying a rotation event:
1. Use `.index` to find the Verfer in the current `k` list
2. Verify the signature against the event serialization using that Verfer
3. Use `.ondex` to find the Diger in the prior `n` list
4. Verify that the Verfer's public key digests to match the Diger
   (pre-rotation commitment check)

For `_Crt_Sig` codes, `.ondex` is None — the signature only references the
current key list. This is used for inception events (no prior next-keys) and
interaction events (no key change).

---

## 8. Signature Verification Algorithm

Given an event serialization `raw`, a list of Sigers, and a list of Verfers:

```
verifySigs(raw, sigers, verfers) → (verified_sigers, verified_indices)

  1. Deduplicate sigers by their qb64 representation
  2. For each siger:
     a. If siger.index >= len(verfers): skip (invalid index)
     b. Assign verfer = verfers[siger.index]
     c. If verfer.verify(siger.raw, raw): mark as verified
     d. Deduplicate by index (first valid signature per index wins)
  3. Return (list of verified sigers, list of verified indices)
```

---

## 9. Threshold Satisfaction Algorithm

Given verified signature indices and a Tholder:

```
tholder.satisfy(indices) → bool

  Numeric (M-of-N):
    return len(set(indices)) >= thold

  Weighted fractional:
    1. Deduplicate and sort indices ascending
    2. Build boolean satisfaction array from indices
    3. Evaluate each AND-clause:
       - Sum weights of verified positions
       - Clause satisfied if sum >= 1
    4. Return true only if ALL clauses satisfied
```

---

## 10. Pre-Rotation Commitment Verification

During rotation, each signer must prove control of a key that was
pre-committed:

```
For each verified siger in rotation event:
  1. current_verfer = current_keys[siger.index]       -- from this event's k field
  2. committed_diger = prior_next_digests[siger.ondex] -- from prior est event's n field
  3. Compute digest of current_verfer.qb64 using committed_diger.code
  4. Verify digest matches committed_diger.raw
  5. If mismatch: signature is INVALID for rotation purposes
```

This ensures that even if an attacker compromises current signing keys, they
cannot rotate without the pre-committed next keys.

---

## 11. Unindexed Signatures (Cigar)

A Cigar is a signature without key-list index tracking. Used for
non-transferable witness receipts and external endorsements.

```
Cigar
  .code         -- CESR code identifying cipher suite
  .raw          -- signature bytes
  .verfer       -- associated Verfer
  .qb64         -- fully qualified CESR string
```

Cigars are verified directly: `cigar.verfer.verify(cigar.raw, serialization)`.
