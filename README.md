# kerizon-ui

A Claude Code plugin that teaches Claude how to derive a **four-panel KERI Human-Agent Collaboration UI** from any KERI ecosystem specification.

## What it does

Given a KERI ecosystem design (roles, credentials, delegation trees, trust framework), the `kerizon-ui` skill produces a complete, domain-specific UI/UX design covering:

- **Panel 1** — Operational View (Credential Portfolio): committed credential state organized by workflow stage
- **Panel 2** — Monitoring View (Watcher View): live TEL/KEL event stream as a domain-aware work timeline with delegation-tree swimlanes
- **Panel 3** — Consultation Chat: orchestrator agent with full credential chain access
- **Panel 4** — Agent Supervision: action queue, reasoning trace, approval gates, interrupt controls

The skill is domain-agnostic — it works for insurance, supply chain, healthcare, education credentials, legal identity, or any other KERI-native domain.

## Installation

### Option 1 — From GitHub (recommended)

Add the marketplace and install the plugin in two steps:

```
/plugin marketplace add seriouscoderone/kerizon
/plugin install kerizon-ui@kerizon
```

The plugin persists across sessions. Verify with `/plugin` → **Installed** tab.

---

### Option 2 — From a local clone

```bash
# Clone the repo
git clone https://github.com/seriouscoderone/kerizon
```

Then from within Claude Code:

```
/plugin marketplace add ./kerizon
/plugin install kerizon-ui@kerizon
```

## Usage

Invoke the skill and provide your ecosystem spec:

```
/kerizon-ui:kerizon-ui

Here is our KERI ecosystem specification: [paste spec]
```

Or Claude will auto-invoke the skill when you describe a KERI ecosystem and ask for a UI design, panel layout, agent supervision screen, or credential monitoring view.

## Key concepts surfaced by the skill

| Concept | Panel |
|---------|-------|
| Workflow-stage credential portfolio | Panel 1 |
| TEL event → Work Unit mapping | Panel 2 |
| Delegation tree swimlanes | Panel 2 |
| Handoff connectors (agent-to-agent) | Panel 2 |
| Witness receipt progress | Panel 2 |
| Orchestrator credential chain queries | Panel 3 |
| Role-lock approval gates (KEL-anchored) | Panel 4 |
| Trust tier derivation from delegation tree | Panel 4 |
| Duplicity handling & suspension | Panel 4 |
| Selective disclosure field gating | All panels |

## Dependency

This plugin requires a **KERI ecosystem specification** as input. The canonical
format — roles with `keri_infrastructure` flags, credentials with `schema_fields`
tables, delegation trees with `depth_limit`, and a governance trust framework — is
defined by the **[keri-claude](https://github.com/seriouscoderone/keri-claude)**
marketplace plugin (`design0-ecosystem` skill).

Install both plugins to go from ecosystem design to UI spec in one session:

```
/plugin marketplace add seriouscoderone/keri-claude
/plugin install design0-ecosystem@keri-claude   # ecosystem design → spec output

/plugin marketplace add seriouscoderone/kerizon
/plugin install kerizon-ui@kerizon              # spec input → four-panel UI design
```

The output of `keri-claude`'s `design0-ecosystem` skill is the direct input to
this skill's Step 1 extraction tables.

## Complementary skills

### kerizon-ui + webapp-blueprint

`kerizon-ui` is a domain-specific UI skill, not a general design system. It produces one canonical design from a KERI ecosystem spec — the fixed four-panel HAC layout driven entirely by KERI primitives (KELs, TELs, ACDCs, delegation trees, witness pools). It covers **Steps 2–9** of a typical web app blueprint: UI paradigm, layout, and panel-level interaction patterns.

A general webapp-blueprint skill covers complementary ground:

| Concern | kerizon-ui | webapp-blueprint |
|---------|-----------|-----------------|
| UI paradigm | Yes — KERI's four-panel HAC layout | No — archetype defaults only |
| Design tokens | No | Yes (Step 3) |
| Page specs | No | Yes (Step 11) |
| Component contracts | No | Yes (Step 12) |
| Domain / roles / APIs / auth | No | Yes (Steps 1–2, 5–9, 13–15) |
| BDD / seed data | No | Yes (Steps 9, 18) |

The two skills complement each other cleanly for a KERI app. The recommended workflow:

1. **Run `/kerizon-ui` first** — produces the four-panel design from your KERI ecosystem spec
2. **Run `/webapp-blueprint`** — use it for Steps 1–9 (domain, roles, BDD) and Steps 13–18 (state, APIs, auth, seed data)
3. **For Steps 10–12** (information architecture, page patterns, component inventory) — reference the `kerizon-ui` output as the source of truth instead of the normal interrogation; the four panels are your IA, your pages, and your primary components

There is no built-in handoff between the two skills, so you coordinate manually: tell Claude explicitly "use kerizon-ui's four-panel output as the answer to Steps 10–12 in webapp-blueprint."

> **Note:** This pattern generalizes. Any domain-specific UI/UX skill (not just `kerizon-ui`) that produces a fixed layout from a domain spec would interact with webapp-blueprint the same way — it answers the IA/pages/components steps while webapp-blueprint handles structural engineering.

`kerizon-ui`'s four-panel design is only appropriate for KERI-native applications. If your app is not KERI-native, `kerizon-ui` output will not apply.

## License

Apache-2.0
