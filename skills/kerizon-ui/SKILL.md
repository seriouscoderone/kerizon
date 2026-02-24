---
name: kerizon-ui
description: >
  Derives a complete four-panel KERI Human-Agent Collaboration UI from a KERI ecosystem
  specification. Use when the user provides a KERI ecosystem spec (roles, credentials,
  delegation trees, trust framework YAML/markdown) and asks for: (1) a UI design or
  panel layout, (2) agent supervision screen design, (3) credential monitoring / watcher
  view design, (4) trust tier configuration for KERI agents, (5) panel-by-panel design
  breakdowns — for any KERI-native domain (insurance, supply chain, healthcare,
  education, legal identity, or other).
user-invocable: true
---

# SKILL — KERI Ecosystem Human-Agent Collaboration UI

## The Four-Panel Paradigm

Every KERI Human-Agent Collaboration UI is built from four panels. Each panel has a
fixed purpose and a fixed relationship to the KERI stack.

```
┌────────────────────────────────────────────────────────────────────┐
│  NAVIGATION                                                         │
├──────────────────────────┬───────────────────────┬─────────────────┤
│                          │                       │                 │
│  PANEL 1                 │  PANEL 2              │  PANEL 3        │
│  Operational View        │  Monitoring View      │  Consultation   │
│  (Credential Portfolio)  │  (Watcher View)       │  Chat           │
│                          │                       │                 │
│  Committed credential    │  Live TEL/KEL event   │  Orchestrator   │
│  state, organized by     │  stream rendered as   │  agent chat     │
│  workflow stage          │  a work timeline      │  with full      │
│                          │                       │  credential     │
│                          │                       │  chain access   │
├──────────────────────────┴───────────────────────┤                 │
│  PANEL 4 — Agent Supervision                     │                 │
│  Action queue, reasoning trace, approval gates,  │                 │
│  direct agent chat, interrupt controls           │                 │
└──────────────────────────────────────────────────┴─────────────────┘
```

**The core insight:** In a KERI ecosystem, the credential chain IS the work log. Every
meaningful agent action results in a signed ACDC credential event anchored in a KEL.
The monitoring view (Panel 2) is therefore a human-readable watcher — consuming the
same TEL and KEL events used for cryptographic verification, rendered for human
comprehension. This means the UI's audit log and the regulatory/governance audit log
are the same artifact.

---

## How to Use This Skill

1. **Start with Step 1 below** — extract role, credential, delegation, and governance
   data from the ecosystem spec. This is mandatory before any design work begins.
2. **Load reference files progressively** as you work through each design phase:
   - `references/domain-adapter.md` for Step 2 (translation layer components)
   - `references/panels.md` for Steps 3–6 (panel-by-panel design specs)
   - `references/trust-and-privacy.md` for Steps 7–8 (trust tiers and privacy)
   - `references/checklist-and-layout.md` for Step 9 and final synthesis

---

## Step 1 — Read the Ecosystem Specification

Before designing any UI, extract the following from the ecosystem documents.

### 1.1 Extract All Roles

From the ecosystem `roles` section, build a role table:

| Field to Extract | UI Purpose |
|-----------------|------------|
| `name` | Agent type identifier, swimlane label |
| `display_name` | Human-readable label throughout the UI |
| `description` | Tooltip and Panel 4 agent definition view |
| `credentials_issued` | What work units this agent can produce |
| `credentials_required` | What credentials gate this agent's authority |
| `keri_infrastructure.witness_pool` | Whether this role needs witness receipt tracking in Panel 2 |
| `keri_infrastructure.watcher_network` | Whether this role participates in the watcher view |
| `keri_infrastructure.agent_service` | Whether this role runs an agent that Panel 4 can supervise |
| `keri_infrastructure.acdc_registry` | Whether this role has an ACDC registry to query |

Roles where `agent_service: true` are candidates for Panel 4 supervision.
Roles where `watcher_network: true` generate events in Panel 2's swimlanes.

### 1.2 Extract All Credentials

From the `credential_catalog`, build the domain adapter for each credential:

| Field to Extract | UI Purpose |
|-----------------|------------|
| `id` | Work Unit type identifier in Panel 2 |
| `name` | Human-readable work unit label |
| `description` | Tooltip in Panel 1 credential cards and Panel 2 timeline |
| `issuer_role` | Which agent type produces this in Panel 4's action queue |
| `holder_role` | Who receives this in Panel 1 |
| `verifier_roles` | Determines which user sessions can view credential field values |
| `schema_fields` | The before/after diff content for Panel 2's diff renderer |
| `disclosure_mode` | `full` = all fields visible to verifiers; `selective` = field-level access control |
| `chained_from` | Parent credential in the chain explorer (Panel 1) |

Map the credential's workflow stage (from the catalog) to Panel 1's stage-organized layout.

### 1.3 Extract All Delegation Trees

From the `delegation_trees` section:

| Field to Extract | UI Purpose |
|-----------------|------------|
| `tree_id` | Swimlane identifier in Panel 2 |
| `root_role` | Root of the swimlane — highest authority in that tree |
| `description` | Swimlane label tooltip |
| `delegates[].role` | Child role in the swimlane hierarchy |
| `delegates[].scope` | Authority scope shown in Panel 4 approval gates |
| `delegates[].depth_limit` | Hard block in Panel 4 if agent tries to exceed this depth |

Each delegation tree becomes a named swimlane in Panel 2. Cross-tree relationships
(e.g., a role that participates in multiple trees) are shown as connector lines.

### 1.4 Extract Governance Rules

From `governance` and trust framework sections, identify:

- **Hard rules** (cannot be overridden): Become automatic blocks in the UI. Examples:
  depth limit exceeded, credential issued outside licensed scope, adverse mid-term actions.
- **Configurable rules** (adjustable defaults): Map to trust tier defaults per role/operation.
- **Privacy rules**: Which credentials are `selective` disclosure and which user roles
  are in `verifier_roles`. These gate field visibility throughout all panels.
- **Dispute resolution tiers**: Map to escalation paths in Panels 3 and 4.

---

## Reference Files

Load these files as you work through each design phase:

| Phase | File | Content |
|-------|------|---------|
| Step 2 | `references/domain-adapter.md` | WorkUnitLabel, DiffRenderer, ArtifactPreview, RiskSignals |
| Steps 3–6 | `references/panels.md` | Panel 1 (Operational), Panel 2 (Monitoring), Panel 3 (Chat), Panel 4 (Supervision) |
| Steps 7–8 | `references/trust-and-privacy.md` | Trust tier derivation, hard override rules, privacy field gating |
| Step 9 | `references/checklist-and-layout.md` | Layout modes, 15-item checklist, anti-patterns |
