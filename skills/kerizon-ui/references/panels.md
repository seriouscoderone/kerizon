# Steps 3–6 — Panel Design Specifications

---

## Step 3 — Panel 1 (Operational View)

### 3.1 Organize by Workflow Stage

Use the credential catalog's stage groupings as Panel 1's primary navigation.
Typical stages: `Authorization → Assessment → Coverage/Agreement → Action/Transaction → Settlement → Intelligence/Reporting`

Your ecosystem's actual stage names come from the credential catalog structure.
Use those exact names — do not rename them.

### 3.2 Credential Card Design

Each issued credential is a card in Panel 1. Every card must show:
- Credential type (from `name` in catalog)
- TEL status badge: `ISSUED` / `REVOKED` / `SUSPENDED` / `PENDING_WITNESS_RECEIPTS`
- Disclosure mode badge: `FULL` or `SELECTIVE`
- Issuer role badge (resolved from `issuer_role`)
- The credential's 2–3 most important identifying fields
- A "chain" indicator showing how many parent credentials this chains from
- Agent attribution badge if issued by an agent (see 3.4)

### 3.3 Chain Explorer

Clicking any credential opens a chain explorer showing the full parent chain from the
root credential to the current one. Render as a directed graph:

```
[root_credential] → [intermediate] → [current]
    ISSUED               ISSUED         ISSUED
```

Show TEL status on each node. A revoked intermediate credential renders the entire
chain below it as potentially compromised — highlight in amber.

### 3.4 Agent Attribution Badges

| Badge | Meaning |
|-------|---------|
| `AGENT-ISSUED` | Agent issued this credential under authority |
| `AGENT-PROPOSED` | Agent proposed; awaiting human promotion (Tier 2) |
| `AGENT-REVOKED` | Agent revoked this credential |
| No badge | Human-issued (baseline) |

### 3.5 Governance Rule Enforcement in Panel 1

Rules that constrain mid-term mutations (e.g., "adverse changes to active agreements
require renewal, not mid-term modification") are enforced in the UI: agent-proposed
credentials that violate these rules are automatically blocked before reaching
`AGENT-PROPOSED` state — they never appear in Panel 1 at all. They surface in Panel 4
as a blocked action with the specific governance rule cited.

---

## Step 4 — Panel 2 (Monitoring View)

### 4.1 Map TEL Events to Work Unit States

| TEL Event | Work Unit Status | Visual Treatment |
|-----------|-----------------|-----------------|
| `iss` (issuance) | `ISSUED` | Green dot |
| `rev` (revocation) | `REVOKED` | Red dot |
| `bis` (backerless issuance) | `LOW_TRUST` | Amber dot with warning |
| `brv` (backerless revocation) | `REVOKED_LOW_TRUST` | Red amber |
| Witness threshold met | `CONFIRMED` | Solid green (replaces hollow) |
| Witness threshold pending | `PENDING_WITNESS_RECEIPTS` | Hollow green with progress bar |

KEL events that surface in the monitoring view:
- `icp` (inception): "New identity established for [role] [AID prefix]"
- `rot` (rotation): "Keys rotated for [role] [AID prefix]" — shown with amber indicator
- Human interrupt events: Shown as `HUMAN-[ACTION]` event type

### 4.2 Delegation Tree Swimlanes

Each delegation tree from the ecosystem spec becomes a labeled swimlane. Place
swimlanes in authority order (root role at top). For a role that participates in
multiple trees, show it in each tree's swimlane with visual links between occurrences.

**Cross-tree relationships** (a credential connecting two independent authority chains)
are shown as horizontal connector lines between swimlanes with the credential type label.

### 4.3 Handoff Events

When an agent in one swimlane issues a credential that is received by an agent in
another swimlane, render a handoff connector:
- Source work unit (issuer swimlane) → Receiving work unit (holder swimlane)
- Connector labeled with the credential type name
- Arrow direction: issuer → holder

Handoffs are the most important visibility event in a multi-agent KERI system.
They make authority delegation physically visible in the timeline.

### 4.4 Witness Receipt Progress

For roles that operate witness pools (`witness_pool: true`), show a witness receipt
progress indicator on `PENDING_WITNESS_RECEIPTS` work units:
`[2 / 3 witnesses confirmed]`

This transitions to `CONFIRMED` when the KAACE threshold is met.

### 4.5 Automatic Escalation Triggers

**From governance hard rules:**
Any agent action that violates a governance hard rule surfaces as an `ALERT` event
in Panel 2 with a `BLOCKED` status, citing the specific rule violated.

**From watcher network:**
`DUPLICITY_DETECTED` — An AID has published conflicting events. This is the most
severe possible event. Render as a **full-width red banner** in Panel 2. Suspend
the agent automatically. The human must actively choose to resume.

---

## Step 5 — Panel 3 (Consultation Chat)

### 5.1 Orchestrator Agent Context

The orchestrator in Panel 3 has read access to the full credential chain for the
current workflow. Implement these named query capabilities:

- **"Why did [agent] do [action]?"** → Traverse the credential chain to surface
  the authority basis and the field values that triggered the action
- **"Is [entity] authorized to [do X]?"** → Verify the credential chain from root
  to the entity's current role credential, checking TEL status at each node
- **"What is the current state of [agreement/credential]?"** → Replay amendments
  from the root credential to reconstruct current terms
- **"What happened while I was away?"** → Summarize Panel 2 events since last session

### 5.2 Orchestrator Action Vocabulary

The orchestrator directs agents but cannot issue credentials directly. It issues
instructions to the agent runtime:

| Generic Action | Behavior |
|----------------|---------|
| Spawn agent | Create a new agent instance with a specific role scope |
| Review credential | Pull credential into chat with DiffRenderer expansion |
| Rollback | Issue TEL `rev` event on the target credential |
| Reassign | Redirect a WAITING agent to a new task |
| Escalate | Freeze relevant agents and mark for external review |

Map these to your ecosystem's workflow verbs when designing the UI affordances.

### 5.3 Plan Summary Widget

A persistent header above the chat showing:
- Active agent names, types, and current status
- Workflow completion as a credential chain progress indicator
  (e.g., "5 of 9 credentials in this workflow issued")
- Open approval gates with their trust tier
- Active governance alerts

---

## Step 6 — Panel 4 (Agent Supervision)

### 6.1 Role-Lock Approval Gates

**The most important design rule in Panel 4:** approval gate authority is determined
by the delegation tree, not by application-layer role configuration.

For each delegation tree in the ecosystem spec, derive the approval authority rule:

```
For each tree:
  An agent operating at [role] under [tree_id]
  can only be approved by a user session presenting
  a valid credential AID for [parent_role in that tree]
  (or root_role if no intermediate parent exists)
```

This is not enforced by application-layer role checks. It requires the approving
user's session to present the appropriate credential AID before the approval event
is recorded to the KEL. Show which credential AID is required, and verify it is
present before enabling the approve button.

### 6.2 Action Queue

Each queued action shows an ArtifactPreview of what the agent intends to issue:
- Credential type and key fields that will be populated
- Chaining edges — which parent credentials will be referenced
- Disclosure mode
- Any RiskSignals detected for this action (shown as inline alerts)

The **Modify** action opens an inline editor for the credential's `a` block fields.
Modified values must still pass RiskSignal evaluation — modifications that introduce
new violations are flagged before the approve button is enabled.

### 6.3 Reasoning Trace — Credential Chain Context

Supplement the agent's natural language reasoning trace with the credential chain
context it is operating against:
- Which credentials the agent has verified (with TEL check timestamps)
- Which TEL revocation checks were performed
- Which credentials the agent is authorized to issue (based on its role credential)
- Any authorization failures encountered (depth limit exceeded, scope mismatch)
- Consent status for each selective disclosure the agent accesses

### 6.4 Duplicity Handling

When the watcher detects duplicity (conflicting events from the same AID):
1. Agent is automatically suspended
2. Panel 4 shows the conflicting event pair side by side
3. Options: **Suspend** (default, pre-selected), **Investigate**, **Report to governance**
4. Per KERI protocol, duplicity constitutes grounds for credential suspension pending
   arbitration. Default to suspension — the human must actively override to continue.

### 6.5 Interrupt Controls

| Control | Behavior |
|---------|---------|
| Pause | Agent completes current micro-action then holds at next credential boundary |
| Stop | Agent halts; partial work preserved as draft |
| Rollback | Agent issues TEL `rev` on its last N credential issuances |
| Handoff | Transfer agent's credential context to a different agent type |
