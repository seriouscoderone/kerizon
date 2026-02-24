# Step 9 — Layout Modes, Checklist, and Anti-Patterns

---

## Step 9 — Layout Modes

### Desktop (default)
Four-panel layout as shown in the paradigm diagram in SKILL.md.
Panels 1 and 2 share the left two-thirds; Panel 3 occupies the right third.
Panel 4 slides up from the bottom when an agent is selected in Panel 2.

### Monitoring Focused
Collapse Panel 1 to a sidebar icon strip. Expand Panels 2 and 4 for active supervision.
Use this mode during multi-agent runs where the human is primarily watching.

### Human Focused
Collapse Panels 2, 3, 4. Full-width Panel 1 for deep domain work when agents are idle.

### Mobile / Narrow
Tab bar: **State | Activity | Chat | Agents** — maps to Panels 1–4 respectively.

---

## Application Checklist

When given a new KERI ecosystem specification, verify all of the following:

- [ ] Extracted all roles and identified which have `agent_service: true`
- [ ] Built the role table with `credentials_issued` and `credentials_required`
- [ ] Mapped every credential to a Work Unit type with a label template
- [ ] Identified `selective` disclosure credentials and their `verifier_roles`
- [ ] Built the DiffRenderer field list for each credential's `schema_fields`
- [ ] Mapped delegation trees to Panel 2 swimlanes
- [ ] Identified cross-tree relationships (connector credentials between swimlanes)
- [ ] Extracted all governance hard rules and mapped them to Blocked RiskSignals
- [ ] Derived trust tier defaults for each role × operation
- [ ] Applied all five hard override rules
- [ ] Designed approval gate role-lock rules from the delegation tree structure
- [ ] Mapped the ecosystem's workflow stages to Panel 1's stage navigation
- [ ] Identified any cross-ecosystem bridge credentials and designed their treatment
- [ ] Confirmed the orchestrator's credential chain query capability covers the
      most common "why did the agent do X" questions for this domain
- [ ] Identified high-volume data streams (IoT equivalent) that need stream view
      rather than per-event timeline entries in Panel 2

---

## Anti-Patterns to Avoid

**Do not design Panel 2 as a generic log viewer.**
Work units must be domain-aware. "Event 4821: credential issued" is not a work unit.
"ISSUED Adjuster License AJ-9921 in WA, OR, ID" is a work unit. Every work unit
label must use the WorkUnitLabel template from `references/domain-adapter.md`.

**Do not make trust tiers a flat application config.**
They are derived from the delegation tree structure. Configuration adjusts defaults
within the permitted range — it does not override the tree-derived authority model.

**Do not show full credential attribute blocks to all users.**
The `verifier_roles` field in each credential definition is a security boundary,
not a suggestion. Apply it as a rendering constraint in every panel.

**Do not treat agent handoffs as internal implementation details.**
Handoffs — where one agent issues a credential that another agent acts upon — are
the most important events in a multi-agent KERI system. Make them first-class visual
events in Panel 2 with explicit connector arrows.

**Do not let agents bypass governance hard rules.**
There is no trust tier that permits an agent to exceed its delegation depth, issue
to a wrong holder role, or proceed after duplicity detection. These are blocks, not
configurable warnings.

**Do not conflate Panel 3 and Panel 4 chat.**
Panel 3 is for the orchestrator — high-level direction and workflow queries.
Panel 4 is for a specific agent instance — corrections, mid-task redirects, and
reasoning inspection. Messages sent in Panel 4 are injected into that agent's
context directly.
