# Ticket 009: Harden product-lifecycle regular-file I/O, strict JSON bounds, and unhashable guards

- **ID**: ticket-009
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden `wellmanifest/product-lifecycle` (`standard/product_primitives.py` and
`standard/conformance.py`): enforce `O_NOFOLLOW | O_NONBLOCK` 4 MiB regular-file
reads and inode stability in `read_regular_utf8` and CLI `--file` validation;
reject `NaN`/`Infinity`, overflow floats (`1e999`/`-1e999`), `RecursionError`,
and nesting deeper than `MAX_JSON_DEPTH = 64` in `strict_loads` and iterative
`reject_sensitive`; reject non-string object keys and unhashable enum values via
`enum_str` so `TypeError: unhashable type` cannot escape `validate_*`; anchor
regexes with `\Z`; add `standard/test_product_hardening.py` without touching
pinned vendored `standard/lifecycle*.py` or schema/grammar/profile artifacts;
and mark merged `ticket-008` `DONE`.

## Acceptance criteria

- [x] AC-01: `standard/product_primitives.py` and `standard/conformance.py` enforce
      `O_NOFOLLOW | O_NONBLOCK` regular-file reads, strict JSON float/depth/key
      bounds, iterative `reject_sensitive`, and `enum_str` unhashable guards while
      keeping all modules `< 500` lines and preserving frozen schema/grammar/lifecycle digests.
- [x] AC-02: `ruff check standard tests`, `python3 standard/conformance.py --all`,
      and `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q` pass.
- [x] AC-03: Close merged `ticket-008`, and pass `./project/governance-check.sh --base origin/main`
      and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
