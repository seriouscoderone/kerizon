# Step 2 — Build the Domain Adapter

The domain adapter is the translation layer between raw KERI/ACDC events and
human-comprehensible UI content. Build four components from the credential catalog.

---

## 2.1 WorkUnitLabel Generator

For each credential type in the catalog, define a label template:

```
Pattern: [VERB] [credential display_name] [key identifier field] [for/by] [actor]

Examples (generic):
  license credential:    "VERIFIED [Role] License [license_id] in [jurisdiction]"
  issuance credential:   "ISSUED [Agreement] [agreement_id] for [holder_aid prefix]"
  decision credential:   "DECIDED [Decision type]: [decision_value] — [basis summary]"
  revocation:            "REVOKED [Credential name] [id] — [reason if present]"
```

Rules for good WorkUnitLabels:
- Always start with a past-tense verb (ISSUED, VERIFIED, FILED, REVOKED, PROPOSED, DECIDED)
- Include the most important scalar identifier field (number, name, or date)
- Include the human actor reference (abbreviated AID or display_name)
- Keep under 80 characters — this is a timeline entry, not a description

---

## 2.2 DiffRenderer

For each credential type, identify which `schema_fields` are most meaningful to diff.
Apply these rendering rules by field type:

| Field Type | Visual Treatment |
|------------|-----------------|
| `number` (monetary) | Currency with +/- delta indicator (green/red) |
| `status` / `decision` enum | Badge: old value → new value with color change |
| `date` | Formatted date + "X days earlier/later" note |
| AID (`string`, 44+ chars) | Truncated: first 8 + `…` + last 4, with role badge via OOBI |
| `string[]` (lists) | Tag diff: additions in green, removals in red |
| `object` | Recurse into key-value pairs and show nested diffs |

**Selective disclosure gating:** For `selective` disclosure credentials, check the
current user's session role against the credential's `verifier_roles`. Fields outside
the user's verifier scope render as `[FIELD CHANGED — restricted]` without values.

**New issuance edge case:** When there is no prior state, show `[NOT ISSUED → ISSUED]`
as the before/after header; then show all `a` block fields as new values.

**Revocation edge case:** Show the `a` block field values that were active at time of
revocation. Overlay a `REVOKED` banner on the diff card.

---

## 2.3 ArtifactPreview

A compact, collapsible card for inline use in Panel 2 timeline entries and Panel 4
action queue items.

**Always include in collapsed state:**
- `TEL status` badge (`ISSUED` / `REVOKED` / `SUSPENDED` / `PENDING_WITNESS_RECEIPTS`)
- `disclosure_mode` badge (`FULL` or `SELECTIVE`)
- Credential type label

**Include:** 3–5 most identifying fields (ID number, jurisdiction, key amounts, dates)

**Exclude from collapsed view:** AID values, hash values, object fields, array fields
(these appear only in the expanded view)

Expanding the card reveals the full `a` block rendered through DiffRenderer.

---

## 2.4 RiskSignals

Scan each ecosystem's governance rules for agent action constraints that should trigger
automatic trust tier escalation. Identify these signal patterns:

| Signal Pattern | Detection Method | Default Severity |
|----------------|-----------------|-----------------|
| Agent exceeds delegation depth | `delegates[].depth_limit` exceeded | CRITICAL — Block |
| Agent issues without required parent credential | `credentials_required` not met | CRITICAL — Block |
| Credential issued to wrong holder role | `holder_role` mismatch | HIGH — Block |
| Agent applies value outside approved list | Schema field referencing approved set | HIGH — Tier 4 |
| Agent issues beyond numeric authority cap | Numeric field with a documented limit | HIGH — Tier 4 |
| Adverse action per governance hard rule | `governance.hard_rules` section match | HIGH — Tier 4 |
| Supplement/amendment exceeds % of original | Compare two linked credential amounts | MEDIUM — Tier 3 |

**Override rule:** For any RiskSignal at HIGH severity, override the configured trust
tier to Tier 4 (step-through). For CRITICAL severity, block entirely. These overrides
are non-configurable — users cannot lower them.
