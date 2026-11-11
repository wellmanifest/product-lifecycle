# Ticket 011: Modularize product_io and harden CLI symlink traversal, JSON int bounds, schema depth, and product name controls

- **ID**: ticket-011
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing security and conformance bugs, modularizing, and optimizing across `wellmanifest/*` standard repositories.

Extract `standard/product_io.py` so regular-file I/O, symlink-ancestor detection, and bounded strict JSON parsing live in a dedicated SSOT module (`product_primitives.py` reduced well below 500 lines); fix the CLI `os.path.abspath` symlink-traversal bypass in `conformance.main` (`sym_dir/../real`) and relative (`../sym_dir`) symlink-parent traversal; bound JSON integer digit lengths before `int()` conversion; replace recursive `Contracts._closed` with an iterative depth-bounded stack; reject blank/multi-line/C0/DEL/surrogate `product.name` values; expand `standard/test_product_hardening.py`; and mark merged `project/ticket-010/README.md` `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `standard/product_io.py`, reject CLI and relative `sym_dir/..` symlink-traversal paths, bound JSON integer digits before `int()`, make `Contracts._closed` iterative with depth bounds, and reject blank/C0/DEL/surrogate `product.name` values, keeping all Python files strictly `< 500` lines.
- [x] AC-02: Expand `standard/test_product_hardening.py`, mark merged `project/ticket-010/README.md` `DONE`, and pass `conformance.py --all`, `ruff check`, `pytest`, `governance-check.sh`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
