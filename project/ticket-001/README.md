# Ticket 001: Define standalone product lifecycle standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-13

## Goal and scope

Define a reusable product-lifecycle standard for versioned products and
services: registration, public release, jurisdiction-aware availability,
restriction, deprecation, withdrawal and sunset. The catalog is independent
of billing and can later back a `wellmanifest/saas-lifecycle` offer.

Legal, license and location rules remain in `wellmanifest/legal-lifecycle`.
This module stores only opaque pack and license references.

## Acceptance criteria

- [x] AC-01: The repository has an immutable published governance adoption and
  a real local seed baseline created before implementation.
- [x] AC-02: A closed Draft 2020-12 schema defines catalog, request, product
  state and receipt variants.
- [x] AC-03: Request-only GBNF excludes marketing copy, prices, credentials
  and deployment coordinates.
- [x] AC-04: Documentation defines the state machine, composition with legal
  and SaaS lifecycles, and fail-closed availability.
- [x] AC-05: Positive and adversarial conformance passes locally and in
  networkless, read-only Docker.
- [x] AC-06: Governance and diff hygiene pass against the exact baseline.

## Authorization

The request to create this repository as a governed DSL project creates
`SESSION_EXECUTION_AUTHORIZATION` and the narrow autonomous seed-baseline
authorization. It allows exactly one local governance-only baseline commit
while `HEAD` is unborn and implementation is absent. It does not authorize a
remote, push, PR, merge, tag or release.

The same request separately authorizes later public repository creation,
committing the bounded implementation, pushing its ticket branch and opening
a pull request. It does not authorize a direct push to `main`, merge, tag or
release creation.

## Baseline

The local seed transaction created
`a21eba0d2e2c0876ad1d0c28aa26058b73df1e05`. Standard implementation begins
after this SHA and bounded delivery uses it as the exact accepted base.

## Participants

- Human participant: unresolved; no `user-*` file was created.
- Agent participant: [ai-grok.md](ai-grok.md)
