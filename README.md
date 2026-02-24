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

### Option 1 — Claude CLI (`--plugin-dir` flag)

Use this to load the plugin for a single session without installing it globally.

```bash
# Clone the repo
git clone https://github.com/seriouscoderone/kerizon

# Launch Claude with the plugin loaded
claude --plugin-dir ./kerizon
```

The plugin is active for that session only. To make it permanent, add it via
`/plugin` instead (see Option 2).

You can verify it loaded by running `/plugins` — `kerizon-ui` should appear in
the list.

---

### Option 2 — Inside Claude Code (`/plugin` command)

If you are already running a Claude Code session, install the plugin without
leaving the session.

**From a local clone:**

```
/plugin install /path/to/kerizon
```

**From the marketplace (once published):**

```
/plugin install seriouscoderone/kerizon
```

After installation, the plugin persists across sessions. Verify with `/plugins`.

---

### Option 3 — Marketplace (once published)

```bash
/plugin marketplace add seriouscoderone/kerizon
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

## License

Apache-2.0
