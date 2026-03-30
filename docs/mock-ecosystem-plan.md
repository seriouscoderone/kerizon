# Mock KERI Ecosystem — Community Demo Plan

## Vision

A working mock ecosystem demonstrating KERI credential flows between real-world participant types: **car dealership**, **bank**, **university**, **municipality**, and **citizen**. All participants use kerizon tools, exchange credentials via IPEX, verify via TEL→KEL chains, and interoperate with keripy via the conformance harness.

## Participants

| Role | Alias | Issues | Verifies |
|------|-------|--------|----------|
| **Municipality** | `springfield` | Residency permits, business licenses | Root governance authority |
| **University** | `state-u` | Diplomas, transcripts | — |
| **Bank** | `first-national` | Creditworthiness, account standing | Employment, residency |
| **Car Dealership** | `acme-motors` | Car loan pre-approval | Diploma, credit, employment, residency |
| **Citizen** | `homer` | — (holder only) | — |

## Credential Schema Catalog

| Schema | Issuer | Fields | Used By |
|--------|--------|--------|---------|
| `ResidencyPermit` | Municipality | holder AID, address, city, issueDate, expiryDate | Bank, Dealership |
| `BusinessLicense` | Municipality | business AID, businessName, licenseType, validUntil | — |
| `UniversityDiploma` | University | holder AID, degree, major, institution, graduationDate | Dealership |
| `ProofOfEmployment` | (any employer) | holder AID, employer, role, startDate, salary | Bank, Dealership |
| `Creditworthiness` | Bank | holder AID, score, tier (excellent/good/fair), assessmentDate | Dealership |
| `CarLoanPreApproval` | Dealership | holder AID, maxAmount, rate, term, validUntil | — |

## Trust Framework (Delegation Tree)

```
Municipality (springfield) — root governance authority
├── authorizes → University (state-u) to issue diplomas
├── authorizes → Bank (first-national) to issue credit assessments
├── authorizes → Car Dealership (acme-motors) to issue loan pre-approvals
└── directly issues → residency permits, business licenses
```

In KERI terms: the municipality creates a delegated inception (`dip`) for each authorized issuer. Each issuer's AID chains back to the municipality's KEL via delegation seals.

## Demo Script — "Homer Gets a Car Loan"

### Phase 1: Bootstrap Identifiers

```bash
# Start witnesses
kerizon witness demo &

# Create each participant's keystore + identifier
for role in municipality university bank dealer citizen; do
  kerizon init --name $role --nopasscode
done

# Resolve witness OOBIs for each
WAN_AID=$(curl -s http://127.0.0.1:5642/oobi/test/witness | grep -o '"i":"[^"]*"' | head -1 | cut -d'"' -f4)
for role in municipality university bank dealer citizen; do
  kerizon oobi resolve --name $role --oobi "http://127.0.0.1:5642/oobi/$WAN_AID/controller" --oobi-alias wan
done

# Incept with witnesses
kerizon incept --name municipality --alias springfield --transferable --wits $WAN_AID --toad 1 --receipt-endpoint
kerizon incept --name university --alias state-u --transferable --wits $WAN_AID --toad 1 --receipt-endpoint
kerizon incept --name bank --alias first-national --transferable --wits $WAN_AID --toad 1 --receipt-endpoint
kerizon incept --name dealer --alias acme-motors --transferable --wits $WAN_AID --toad 1 --receipt-endpoint
kerizon incept --name citizen --alias homer --transferable --wits $WAN_AID --toad 1 --receipt-endpoint
```

### Phase 2: Publish Schemas

Each schema is a JSON Schema document, SAIDified and hosted via witness OOBI.

```typescript
import { Saider } from '@kerizon/cesr';

// Residency Permit schema
const residencySchema = Saider.saidify({
  "$id": "",
  "$schema": "http://json-schema.org/draft/2020-12/schema",
  "title": "Residency Permit",
  "type": "object",
  "credentialType": "ResidencyPermit",
  "properties": {
    "i": { "type": "string", "description": "holder AID" },
    "address": { "type": "string" },
    "city": { "type": "string" },
    "issueDate": { "type": "string", "format": "date" },
    "expiryDate": { "type": "string", "format": "date" }
  },
  "required": ["i", "address", "city", "issueDate"]
}, '$id', 'E');
// residencySchema.$id = "EResidencySAID..." — publish at any URL

// University Diploma schema
const diplomaSchema = Saider.saidify({
  "$id": "",
  "$schema": "http://json-schema.org/draft/2020-12/schema",
  "title": "University Diploma",
  "type": "object",
  "credentialType": "UniversityDiploma",
  "properties": {
    "i": { "type": "string", "description": "holder AID" },
    "degree": { "type": "string" },
    "major": { "type": "string" },
    "institution": { "type": "string" },
    "graduationDate": { "type": "string", "format": "date" }
  },
  "required": ["i", "degree", "institution", "graduationDate"]
}, '$id', 'E');

// Creditworthiness schema
const creditSchema = Saider.saidify({
  "$id": "",
  "$schema": "http://json-schema.org/draft/2020-12/schema",
  "title": "Creditworthiness Assessment",
  "type": "object",
  "credentialType": "Creditworthiness",
  "properties": {
    "i": { "type": "string", "description": "holder AID" },
    "score": { "type": "integer", "minimum": 300, "maximum": 850 },
    "tier": { "type": "string", "enum": ["excellent", "good", "fair", "poor"] },
    "assessmentDate": { "type": "string", "format": "date" }
  },
  "required": ["i", "score", "tier", "assessmentDate"]
}, '$id', 'E');

// Car Loan Pre-Approval schema
const loanSchema = Saider.saidify({
  "$id": "",
  "$schema": "http://json-schema.org/draft/2020-12/schema",
  "title": "Car Loan Pre-Approval",
  "type": "object",
  "credentialType": "CarLoanPreApproval",
  "properties": {
    "i": { "type": "string", "description": "holder AID" },
    "maxAmount": { "type": "number" },
    "rate": { "type": "number" },
    "termMonths": { "type": "integer" },
    "validUntil": { "type": "string", "format": "date" }
  },
  "required": ["i", "maxAmount", "rate", "termMonths"]
}, '$id', 'E');
```

### Phase 3: Create Credential Registries

```bash
# Each issuer creates a registry for their credential type
kerizon vc registry incept --name municipality --alias springfield --registry-name residency-permits
kerizon vc registry incept --name university --alias state-u --registry-name diplomas
kerizon vc registry incept --name bank --alias first-national --registry-name credit-assessments
kerizon vc registry incept --name dealer --alias acme-motors --registry-name loan-approvals
```

### Phase 4: Issue Credentials to Homer

```bash
# Municipality issues residency permit
cat > /tmp/residency-data.json << 'EOF'
{
  "i": "<homer-prefix>",
  "address": "742 Evergreen Terrace",
  "city": "Springfield",
  "issueDate": "2026-01-15",
  "expiryDate": "2027-01-15"
}
EOF
kerizon vc create --name municipality --alias springfield \
  --registry-name residency-permits \
  --schema <residency-schema-SAID> \
  --data @/tmp/residency-data.json

# University issues diploma
cat > /tmp/diploma-data.json << 'EOF'
{
  "i": "<homer-prefix>",
  "degree": "Bachelor of Science",
  "major": "Nuclear Engineering",
  "institution": "Springfield State University",
  "graduationDate": "2020-06-15"
}
EOF
kerizon vc create --name university --alias state-u \
  --registry-name diplomas \
  --schema <diploma-schema-SAID> \
  --data @/tmp/diploma-data.json

# Bank issues creditworthiness assessment
cat > /tmp/credit-data.json << 'EOF'
{
  "i": "<homer-prefix>",
  "score": 720,
  "tier": "good",
  "assessmentDate": "2026-03-01"
}
EOF
kerizon vc create --name bank --alias first-national \
  --registry-name credit-assessments \
  --schema <credit-schema-SAID> \
  --data @/tmp/credit-data.json
```

### Phase 5: IPEX Exchange — Homer Applies for Car Loan

This is the core credential exchange flow using the `@kerizon/keri-core` IPEX API:

```typescript
import {
  buildApply, buildGrant, buildAdmit,
  NegotiationStateMachine,
  CredentialLifecycle,
} from '@kerizon/keri-core';

// 1. Acme Motors requests credentials from Homer
const apply = buildApply({
  sender: acmePrefix,
  recipient: homerPrefix,
  schema: diplomaSchemaSaid,  // "I need your diploma"
  datetime: new Date().toISOString(),
});

// 2. Homer's agent responds with the credential
const grant = buildGrant({
  sender: homerPrefix,
  recipient: acmePrefix,
  acdc: homerDiplomaAcdc,
  prior: apply.said,
  datetime: new Date().toISOString(),
});

// 3. Acme verifies the credential chain:
//    ACDC SAID → TEL (not revoked?) → KEL (issuer legit?) → Schema (correct?)
import { verifyCredentialArtifacts, verifyProofChain } from '@kerizon/keri-core';

const artifactCheck = verifyCredentialArtifacts({
  acdcSaid: homerDiplomaAcdc.d,
  telEventSaid: telIssuanceSaid,
  kelSealSaid: kelAnchorSaid,
  issuerAid: universityPrefix,
});
// artifactCheck.verified === true

// 4. Acme admits the credential
const admit = buildAdmit({
  sender: acmePrefix,
  recipient: homerPrefix,
  grantSaid: grant.said,
  datetime: new Date().toISOString(),
});

// 5. Repeat for creditworthiness and residency credentials

// 6. Acme issues car loan pre-approval to Homer
const loanApproval = buildGrant({
  sender: acmePrefix,
  recipient: homerPrefix,
  acdc: {
    d: '', i: acmePrefix,
    s: loanSchemaSaid,
    a: { i: homerPrefix, maxAmount: 35000, rate: 4.5, termMonths: 60 },
  },
  datetime: new Date().toISOString(),
});
```

### Phase 6: Cross-Implementation Verification

Prove the entire ecosystem works across KERI implementations:

```bash
# Export Homer's credential chain from kerizon
kerizon export --name citizen --alias homer > homer-kel.cesr
kerizon export --name university --alias state-u > university-kel.cesr
kerizon export --name bank --alias first-national > bank-kel.cesr

# Import into kli (keripy) and verify
kli init --name verifier --nopasscode
kli import --name verifier --file homer-kel.cesr
kli import --name verifier --file university-kel.cesr
kli import --name verifier --file bank-kel.cesr

# kli can now verify Homer's credentials were issued by legitimate entities
# and the KEL chain is intact
```

## Implementation as a Script

The demo can be packaged as a single TypeScript script:

```
mock-ecosystem/
  package.json          # depends on @kerizon/cesr, @kerizon/keri-core, @kerizon/discovery
  src/
    schemas.ts          # Schema definitions (SAIDified)
    participants.ts     # Create all participants via kerizon-cli
    issue.ts            # Issue credentials to Homer
    exchange.ts         # IPEX flow: Homer applies for car loan
    verify.ts           # Cross-impl verification with kli
    demo.ts             # Main: runs all steps in sequence
```

## What This Proves

1. **KERI works for real business scenarios** — not just protocol tests
2. **Schemas are emergent** — anyone can publish, SAID guarantees integrity
3. **Credential exchange is standardized** — IPEX 6-step flow works for any credential type
4. **Cross-implementation interop** — kerizon ↔ keripy at every level (KEL, signatures, witnesses)
5. **Decentralized trust** — no central authority needed for schemas, registries, or verification
6. **Everything is cryptographically verifiable** — ACDC → TEL → KEL → Witness chain

## Next Steps

1. Build the `mock-ecosystem/` package as a runnable script
2. Add a simple web UI showing the credential exchange visually
3. Extend with: proof of employment (employer role), insurance (insurer role)
4. Demonstrate revocation: university revokes Homer's diploma, car dealership detects it
5. Demonstrate rotation: bank rotates keys, existing credentials still verify via KEL chain
