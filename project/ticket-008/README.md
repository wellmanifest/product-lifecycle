# Ticket 008: Add pytest conformance suite for product-lifecycle v1

- **ID**: ticket-008
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Add a standalone `pytest` / `unittest` conformance suite under
`tests/test_product_lifecycle.py` exercising `product-lifecycle` v1 conformance
reports, strict JSON duplicate-key rejection, `bool`-for-`int` rejection,
unhashable entitlement list handling, ISO-8601 sunset date validation, receipt
outcome validation, inline credential scanning, and `--file` CLI exit codes, and
close merged `ticket-007`.

## Acceptance criteria

- [x] AC-01: Add `tests/test_product_lifecycle.py` exercising `product-lifecycle`
      v1 validators and `--file` CLI under both `pytest` and `unittest`.
- [x] AC-02: Reconcile merged `project/ticket-007/README.md` to `DONE` /
      `PUBLICATION` and pass `ruff check tests`, `pytest -q`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
