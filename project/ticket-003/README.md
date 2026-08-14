# Ticket 003: Require Lifecycle DSL conformance in CI

- **ID**: ticket-003
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-14

## Goal and scope

Make the canonical offline Lifecycle DSL conformance command a mandatory,
visible GitHub Actions check on every pull request and every push to `main`.
The workflow must reuse the vendored validator and local domain profile without
adding runtime dependencies or changing lifecycle semantics.

## Acceptance criteria

- [x] AC-01: GitHub Actions runs `python3 standard/conformance.py --all` on
  pull requests, pushes to `main`, and manual dispatches.
- [x] AC-02: The job is named `standards / lifecycle conformance` and uses
  commit-pinned checkout/setup actions with Python 3.12.
- [x] AC-03: Existing domain conformance and governance gates pass unchanged.
- [x] AC-04: The change adds no dependency and grants only read access.

## Risks

- A local-only command is easy to bypass; the PR and default-branch triggers
  therefore form part of the contract.
- Mutable action tags could change the gate without review; action revisions
  are pinned by commit SHA.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
