# Ticket 004: Adopt wellmanifest/new-project v0.20.32 and host source links

- **ID**: ticket-004
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-09-15

## Goal and scope

Upgrade this adopter from `wellmanifest/new-project` 0.16.0 to the published
0.20.32 revision. The upgrade is performed only through the managed Goal
adoption transaction and installs the complete host-agnostic contract,
including bounded-session continuation, anomaly checks and concrete source
links in every declared agent host projection.

The local adoption lock and managed-file digests remain authoritative. Remote
Wellmanifest URLs are navigation only. Product lifecycle schemas and domain
files remain unchanged.

## Acceptance criteria

- [x] AC-01: The user's autonomous execution request is recorded as
  `SESSION_EXECUTION_AUTHORIZATION` and bounds this ticket to this adopter and
  its protected publication boundary.
- [ ] AC-02: The complete published 0.20.32 managed package is adopted from
  `b6ba9c21a65a6a5648ecf904b64c3b75295e136f`, with the lock and package map
  proving the exact source revision and managed digests.
- [ ] AC-03: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor, Aider and Copilot
  projections contain the standard source-links contract.
- [ ] AC-04: Governance, product lifecycle conformance and diff checks pass;
  no domain or human-owned file is changed.
- [ ] AC-05: The exact ticket HEAD is published through protected PR and
  trusted review; no direct merge is performed by the agent.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Boundaries

- Existing target-owned files are preserved unless the managed adoption
  transaction proves the exact package binding.
- This ticket upgrades one repository only; other adopters require separate
  serialized allocation and review.

SESSION_EXECUTION_AUTHORIZATION: the user requested continuation and
repository-wide standardization/testing. This ticket applies that authority to
this clean `product-lifecycle` adopter only, within the declared intent and
protected publication boundary.
