#!/usr/bin/env python3
"""Shared contract primitives and Lifecycle DSL profile check for product-lifecycle v1."""

from __future__ import annotations

import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import lifecycle  # noqa: E402
from product_io import (  # noqa: E402
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_INT_ABS,
    MAX_JSON_INT_DIGITS,
    ContractError,
    canonical,
    digest,
    enforce_json_bounds,
    file_digest,
    has_control_chars,
    has_symlink_ancestor,
    is_valid_utf8,
    read_regular_bytes,
    read_regular_utf8,
    strict_loads,
)

SCHEMA_URI = "https://wellmanifest.dev/schemas/product-lifecycle/v1"
SCHEMA_PATH = ROOT / "product-lifecycle.schema.json"
GRAMMAR_PATH = ROOT / "product-lifecycle.v1.gbnf"
LIFECYCLE_PATH = ROOT / "product-lifecycle.lifecycle"
SCHEMA_DIGEST = "d80ab5ddb5e3393f83261c29f53ad4e60be4855f3d5d8f6d1d1dd6dd5f8b87c6"
GRAMMAR_DIGEST = "f54372cd1e613b3d120a577987937fc7e3cc7dd795a246ecffad155d16e32f56"
LIFECYCLE_SOURCE_REVISION = "12bdc4c899bd6119cc30fca51d00a62b8582fa79"
LIFECYCLE_VALIDATOR_DIGESTS = {
    "lifecycle.py": "c0fdaad649f9740a894e785686a3d78f0d9a18e914ba7d5d5c673498326b8f71",
    "lifecycle_audit.py": "758c08401214c0be16dc5be8c28fc6be026e95050b1df87e62ea77b06a412459",
    "lifecycle_catalog.py": "9fcbd3a5922c617801640cb4cfd27a29398b8dda387d55060dbfef68be12898d",
}
LIFECYCLE_PROFILE_DIGEST = "61431f23dcf101ded3250ffe590957936cac8677ba2e4a83c8e06c653ca68c47"
SENSITIVE = re.compile(
    r"(?:password|passwd|token|secret|cookie|api[-_]?key|card|cvv|private[-_]?key|"
    r"price|amount|currency|settlement|hostname|ssh|docroot|marketing[-_]?copy)",
    re.I,
)
SECRET_MATERIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRI"
    r"VATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b|"
    r"(?:password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)
SAFE_ASSERTIONS = {"secretsRedacted", "commercialDataStored"}
RFC3339_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
ISO_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")
SEMVER_RE = re.compile(r"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?\Z")
STAGES = {
    "draft",
    "preview",
    "generally-available",
    "restricted",
    "deprecated",
    "withdrawn",
    "sunset",
}
ALLOWED_OUTCOMES = {
    "denied",
    "registered",
    "released",
    "restricted",
    "deprecated",
    "withdrawn",
    "sunset",
    "failed",
}
LIFECYCLE_TRANSITIONS = {
    ("DRAFT", "PREVIEW", "REGISTER"),
    ("DRAFT", "GENERALLY_AVAILABLE", "RELEASE"),
    ("PREVIEW", "GENERALLY_AVAILABLE", "RELEASE"),
    ("GENERALLY_AVAILABLE", "RESTRICTED", "RESTRICT"),
    ("GENERALLY_AVAILABLE", "DEPRECATED", "DEPRECATE"),
    ("GENERALLY_AVAILABLE", "WITHDRAWN", "WITHDRAW"),
    ("RESTRICTED", "DEPRECATED", "DEPRECATE"),
    ("RESTRICTED", "WITHDRAWN", "WITHDRAW"),
    ("DEPRECATED", "WITHDRAWN", "WITHDRAW"),
    ("WITHDRAWN", "SUNSET", "SUNSET"),
    ("DEPRECATED", "SUNSET", "SUNSET"),
}

__all__ = [
    "ALLOWED_OUTCOMES",
    "ContractError",
    "Contracts",
    "GRAMMAR_DIGEST",
    "GRAMMAR_PATH",
    "ISO_DATE_RE",
    "LIFECYCLE_PATH",
    "LIFECYCLE_PROFILE_DIGEST",
    "LIFECYCLE_SOURCE_REVISION",
    "LIFECYCLE_TRANSITIONS",
    "LIFECYCLE_VALIDATOR_DIGESTS",
    "MAX_INPUT_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_INT_ABS",
    "MAX_JSON_INT_DIGITS",
    "RFC3339_RE",
    "ROOT",
    "SAFE_ASSERTIONS",
    "SCHEMA_DIGEST",
    "SCHEMA_PATH",
    "SCHEMA_URI",
    "SECRET_MATERIAL",
    "SEMVER_RE",
    "SENSITIVE",
    "STAGES",
    "bounded_int",
    "bounded_list",
    "canonical",
    "digest",
    "enforce_json_bounds",
    "enum_str",
    "exact",
    "file_digest",
    "has_control_chars",
    "has_symlink_ancestor",
    "is_valid_utf8",
    "iso_date_value",
    "read_regular_bytes",
    "read_regular_utf8",
    "reject_sensitive",
    "strict_bool",
    "strict_loads",
    "time_value",
    "unique_list",
    "validate_lifecycle_profile",
]


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    if any(not isinstance(k, str) for k in value):
        raise ContractError("JSON object key must be a string")
    optional_keys = optional or set()
    if set(value) - required - optional_keys:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing field")
    return value


def enum_str(value: Any, allowed: set[str], message: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ContractError(message)
    return value


def bounded_int(value: Any, minimum: int, maximum: int, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(message)
    return value


def strict_bool(value: Any, message: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(message)
    return value


def bounded_list(value: Any, message: str, *, minimum: int = 0, maximum: int = 64) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContractError(message)
    return value


def unique_list(value: Any, message: str, *, minimum: int = 0, maximum: int = 64) -> list[Any]:
    items = bounded_list(value, message, minimum=minimum, maximum=maximum)
    try:
        is_unique = len(items) == len(set(items))
    except TypeError as error:
        raise ContractError(message) from error
    if not is_unique:
        raise ContractError(message)
    return items


def time_value(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or RFC3339_RE.fullmatch(value) is None:
        raise ContractError("invalid date-time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("invalid date-time") from error
    if result.tzinfo is None:
        raise ContractError("timezone required")
    return result


def iso_date_value(value: Any) -> date:
    if not isinstance(value, str) or ISO_DATE_RE.fullmatch(value) is None:
        raise ContractError("invalid sunset date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ContractError("invalid sunset date") from error


def reject_sensitive(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("JSON nesting depth exceeded")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str) or not is_valid_utf8(key):
                    raise ContractError("JSON object key must be valid UTF-8 text")
                if SENSITIVE.search(key) and key not in SAFE_ASSERTIONS:
                    raise ContractError("sensitive data channel")
                if SECRET_MATERIAL.search(key):
                    raise ContractError("credential material is forbidden")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            if not is_valid_utf8(current):
                raise ContractError("invalid UTF-8 surrogate in JSON string")
            if SECRET_MATERIAL.search(current):
                raise ContractError("credential material is forbidden")


def validate_lifecycle_profile(schema: dict[str, Any]) -> None:
    for filename, expected_sha in LIFECYCLE_VALIDATOR_DIGESTS.items():
        if file_digest(ROOT / filename) != expected_sha:
            raise ContractError(f"pinned lifecycle validator digest mismatch: {filename}")
    if file_digest(LIFECYCLE_PATH) != LIFECYCLE_PROFILE_DIGEST:
        raise ContractError("pinned lifecycle profile digest mismatch")
    report = lifecycle.validate_path(LIFECYCLE_PATH, lifecycle.embedded_catalog())
    if not report.valid or len(report.lifecycles) != 1:
        raise ContractError("Lifecycle DSL profile is invalid")
    if lifecycle.audit_path(LIFECYCLE_PATH)["finding_count"] != 0:
        raise ContractError("Lifecycle DSL profile has compaction findings")
    model = report.lifecycles[0]
    state_values = schema["$defs"]["stage"]["enum"]
    expected_states = {str(val).upper().replace("-", "_") for val in state_values}
    actual_transitions = {(item.source, item.target, item.event) for item in model.transitions}
    if model.name != "product-release" or set(model.states) != expected_states:
        raise ContractError("Lifecycle DSL state graph mismatch")
    if actual_transitions != LIFECYCLE_TRANSITIONS:
        raise ContractError("Lifecycle DSL transition graph mismatch")
    if model.summary()["initial_state"] != "DRAFT":
        raise ContractError("Lifecycle DSL initial state mismatch")
    if model.summary()["terminal_states"] != ["SUNSET"]:
        raise ContractError("Lifecycle DSL terminal state mismatch")


class Contracts:
    def __init__(self) -> None:
        self.schema = strict_loads(read_regular_utf8(SCHEMA_PATH))
        self.grammar = read_regular_utf8(GRAMMAR_PATH)
        defs = self.schema.get("$defs", {})
        names = (
            "identifier",
            "sha256",
            "productRef",
            "catalogRef",
            "packRef",
            "licenseRef",
            "jurisdictionRef",
            "entitlementRef",
            "intentRef",
            "grantRef",
            "evidenceRef",
        )
        self.patterns = {
            name: re.compile(
                r"\A" + defs[name]["pattern"][1:-1] + r"\Z"
                if defs[name]["pattern"].startswith("^") and defs[name]["pattern"].endswith("$")
                else defs[name]["pattern"]
            )
            for name in names
        }
        self.max_lengths = {
            name: defs[name]["maxLength"] for name in names if "maxLength" in defs[name]
        }

    def ref(self, name: str, value: Any) -> str:
        max_len = self.max_lengths.get(name)
        if (
            not isinstance(value, str)
            or not is_valid_utf8(value)
            or (max_len is not None and len(value) > max_len)
            or self.patterns[name].fullmatch(value) is None
        ):
            raise ContractError(f"invalid {name}")
        if "://" in value:
            host, _, rest = value.split("://", 1)[1].partition("/")
            if host in {"", ".", ".."} or any(
                seg in {"", ".", ".."} for seg in re.split(r"[/:]", rest)
            ):
                raise ContractError(f"invalid {name}")
        return value

    def integrity(self) -> None:
        if (
            self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or self.schema.get("$id") != SCHEMA_URI
        ):
            raise ContractError("schema identity mismatch")
        if (
            digest(canonical(self.schema)) != SCHEMA_DIGEST
            or digest(self.grammar) != GRAMMAR_DIGEST
        ):
            raise ContractError("contract digest mismatch")
        expected_variants = {
            "#/$defs/catalog",
            "#/$defs/request",
            "#/$defs/lifecycle",
            "#/$defs/receipt",
        }
        if {x.get("$ref") for x in self.schema.get("oneOf", [])} != expected_variants:
            raise ContractError("document variants incomplete")
        fragments = (
            "root ::= request",
            "marketing copy",
            "product-ref ::=",
            "catalog-ref ::=",
            "sha256 ::=",
        )
        if any(fragment not in self.grammar for fragment in fragments):
            raise ContractError("grammar incomplete")
        self._closed(self.schema)

    def _closed(self, value: Any) -> None:
        stack: list[tuple[Any, int]] = [(value, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > MAX_JSON_DEPTH:
                raise ContractError("schema nesting depth exceeded")
            if isinstance(current, dict):
                if (
                    current.get("type") == "object"
                    and current.get("additionalProperties") is not False
                ):
                    raise ContractError("open object schema")
                for child in current.values():
                    if isinstance(child, (dict, list)):
                        stack.append((child, depth + 1))
            elif isinstance(current, list):
                for child in current:
                    if isinstance(child, (dict, list)):
                        stack.append((child, depth + 1))
