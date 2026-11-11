# Ticket 007: Modularize product-lifecycle under 500 lines and harden strict validation

- **ID**: ticket-007
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Sync the modularized `< 500`-line Lifecycle DSL validator from
`wellmanifest/lifecycle@12bdc4c899bd6119cc30fca51d00a62b8582fa79` (`lifecycle.py`,
`lifecycle_audit.py`, `lifecycle_catalog.py`), split `standard/conformance.py`
under 500 lines (`product_primitives.py`, `product_fixtures.py`, `conformance.py`),
remove `(KeyError, TypeError)` exception masking in `run_all()`, enforce full JSON
Schema parity (`catalog.version` semver, `catalog.products` bounds, `product.public`
strict bool, `product.entitlements` uniqueness/bounds, `state.version` `bool`-safe
integer, `state.sunsetAt` strict `YYYY-MM-DD`, `receipt.outcome` enum,
`receipt.evidenceRefs` uniqueness/bounds, `$defs` `maxLength`), enforce strict
duplicate-key JSON rejection and inline credential scanning, add `--file` CLI and
`pyproject.toml`, and reconcile merged `ticket-004` and `ticket-006`.

## Acceptance criteria

- [x] AC-01: Sync modularized `wellmanifest/lifecycle@12bdc4c8` validator and
      split `standard/conformance.py` so every `.py` module is strictly `< 500`
      lines and passes `ruff check standard`.
- [x] AC-02: Enforce full schema parity, duplicate-key JSON rejection,
      `bool`-for-`int` rejection, unhashable list handling, strict RFC3339 /
      ISO-date formats, and inline credential scanning, passing
      `python3 standard/conformance.py --all` and networkless Docker execution.
- [x] AC-03: Add `pyproject.toml`, close merged `ticket-004` and `ticket-006`,
      and pass `./project/governance-check.sh --base origin/main` and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
