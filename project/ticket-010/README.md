# Ticket 010: Harden product_primitives JSON overflow/surrogates, ancestor symlinks, secret keys, and ref bounds

- **ID**: ticket-010
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing security and conformance bugs, and optimizing across `wellmanifest/*` standard repositories.

Harden `standard/product_primitives.py` and `standard/conformance.py` by anchoring regexes and compiled schema `$defs` patterns with `\A...\Z`, enforcing URI host/segment traversal bounds (`.`, `..`, empty `/` or `:` segments) in `Contracts.ref`, rejecting `10**400` JSON integer overflow, 4300+ digit integers, malformed JSON, and lone UTF-16 surrogates across `_enforce_json_bounds`, `strict_loads`, `canonical`, `digest`, and `reject_sensitive`, scanning JSON object keys with `SECRET_MATERIAL`, enforcing positive integer `max_bytes` and relative + deep absolute symlink-ancestor rejection in `read_regular_bytes`, `read_regular_utf8`, and `file_digest`, passing `allow_nan=False` in `conformance.py` CLI output, expanding `standard/test_product_hardening.py`, and closing merged `project/ticket-009/README.md` (`DONE`).

## Acceptance criteria

- [x] AC-01: Reject `10**400` JSON integer overflow, 4300+ digit integers, malformed JSON, and lone UTF-16 surrogates across `_enforce_json_bounds`, `strict_loads`, `canonical`, `digest`, and `reject_sensitive`, and scan JSON object keys with `SECRET_MATERIAL`.
- [x] AC-02: Enforce positive integer `max_bytes` and relative + deep absolute symlink-ancestor rejection in `read_regular_bytes`, `read_regular_utf8`, and `file_digest`, anchor regexes with `\A...\Z`, and enforce URI segment traversal bounds in `Contracts.ref`, keeping all Python files strictly `< 500` lines.
- [x] AC-03: Expand `standard/test_product_hardening.py`, mark merged `project/ticket-009/README.md` `DONE`, and pass `conformance.py --all`, `ruff check`, `pytest`, `governance-check.sh`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
