# Steps 7–8 — Trust Tiers and Privacy Constraints

---

## Step 7 — Map Trust Tiers

Trust tiers govern how much autonomy each agent has. Derive defaults from the
ecosystem specification, then apply the hard override rules.

### 7.1 Default Trust Tier Derivation

For each role × operation combination, set a default tier based on:

| Heuristic | Suggested Default Tier |
|-----------|----------------------|
| Root authority roles (regulator equivalent) | Tier 4 — Step-through always |
| Credentials that chain from root (primary licenses) | Tier 3 — Approve each |
| Credentials that delegate authority to others | Tier 2 — Advise (draft review) |
| Operational credentials (assessment, scoping, data) | Tier 1 — Inform |
| Autonomous data ingestion (IoT, sensor streams) | Tier 0 — Autonomous |
| Financial commitment credentials | Tier 3 or Tier 4 depending on amount |

### 7.2 Hard Override Rules

These five overrides apply universally regardless of ecosystem domain or user
configuration. They are non-configurable blocks:

1. **Credential issued beyond delegation tree depth limit** → Blocked (cannot proceed)
2. **Credential issued to wrong holder role** → Blocked
3. **Credential issued without required parent credential** → Blocked
4. **Duplicity detected on agent AID** → Suspended (human must resume)
5. **Governance hard rule violated** → Blocked (cite rule in Panel 4)

No trust tier permits bypassing these rules. There is no "step-through" for a blocked
action — it must be resolved at the governance or credential level.

### 7.3 Trust Tier Reference

| Tier | Name | Behavior |
|------|------|---------|
| 0 | Autonomous | Issues and commits without approval. Appears in Panel 2 monitoring only. |
| 1 | Inform | Issues and commits; sends summary to Panel 3 chat after significant actions. |
| 2 | Advise | Produces `AGENT-PROPOSED` draft; human must promote to `ISSUED`. |
| 3 | Approve | Pauses at each credential boundary; requires explicit sign-off in Panel 4. |
| 4 | Step-Through | Pauses before every individual field population. High-risk or debug mode. |

---

## Step 8 — Privacy Constraints

Apply the ecosystem's privacy rules as a rendering constraint throughout all panels.

### 8.1 Verifier-Role Field Gating

For every credential with `disclosure_mode: selective`:
- Check the current user's session role against the credential's `verifier_roles`
- If the user's role is **not** in `verifier_roles`: render the field as `[restricted]`
- Apply this constraint in:
  - Panel 1 (credential card field values)
  - Panel 2 (DiffRenderer field values)
  - Panel 4 (action queue ArtifactPreview and Modify editor)

The `verifier_roles` field is a security boundary, not a suggestion.

### 8.2 Consent Edge Block Indicators

For credentials that include consent edges on data sharing:
- Show a `[CONSENT GATED]` indicator on the work unit in Panel 2
- Panel 4's agent reasoning trace shows consent status for each disclosure made
- A selective disclosure credential presented without a consent edge block is a
  governance violation — flag as a RiskSignal (see `references/domain-adapter.md`)

### 8.3 AID Display

AIDs are long cryptographic strings. Display them consistently across all panels:
- **Truncated format:** first 8 chars + `…` + last 4 chars
- **Role badge:** resolved via OOBI lookup (show the role name next to the AID)
- **Hover tooltip:** shows the full AID and its current KEL event count / status
