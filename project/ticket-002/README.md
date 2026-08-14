# Ticket 002: Adopt shared Lifecycle DSL profile

- **ID**: ticket-002
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-14

## Goal and scope

Adopt Lifecycle DSL v1 as a byte-pinned, offline structural gate for the
product release contract. Publish the exact local state graph in
`standard/product-lifecycle.lifecycle`, validate it with the shared standalone validator,
and require domain conformance to prove that the projected states and edges
match the owning schema and documentation without widening authority.

## Acceptance criteria

- [x] AC-01: The local Lifecycle DSL profile validates offline with the
  byte-identical shared validator pinned to lifecycle revision
  `4b5e131a670afb46ca87291479fed7c0fefcf370`.
- [x] AC-02: Domain conformance rejects validator or profile digest drift.
- [x] AC-03: Domain conformance proves exact state and transition equality
  between the profile and the owning product release contract.
- [x] AC-04: Existing positive and adversarial behavior remains unchanged and
  passes in the networkless project container.
- [x] AC-05: Adopted governance passes with no dependency or domain authority
  expansion.

## Risks

- A merely valid DSL file could still contradict the domain graph. Exact
  state/edge comparison is therefore mandatory.
- Vendored validator bytes could drift from their declared source. A pinned
  SHA-256 check fails closed before profile validation.
- The profile is descriptive and cannot authorize or execute a transition.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
