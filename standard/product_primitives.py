#!/usr/bin/env python3
"""Shared contract primitives and Lifecycle DSL profile check for product-lifecycle v1."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
from datetime import date, datetime
from pathlib import Path
from typing import Any

import lifecycle

ROOT = Path(__file__).resolve().parent
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
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
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"(?:password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)
SAFE_ASSERTIONS = {"secretsRedacted", "commercialDataStored"}
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?\Z")
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


class ContractError(ValueError):
    """A bounded error that never repeats untrusted commercial or host data."""


def _enforce_json_bounds(root: Any, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ContractError("JSON nesting depth exceeded")
        if isinstance(current, float) and not math.isfinite(current):
            raise ContractError("non-finite JSON float is forbidden")
        if isinstance(current, dict):
            next_depth = depth + 1
            if next_depth > max_depth and current:
                raise ContractError("JSON nesting depth exceeded")
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("JSON object key must be a string")
                if isinstance(child, (dict, list, float)):
                    stack.append((child, next_depth))
        elif isinstance(current, list):
            next_depth = depth + 1
            if next_depth > max_depth and current:
                raise ContractError("JSON nesting depth exceeded")
            for child in current:
                if isinstance(child, (dict, list, float)):
                    stack.append((child, next_depth))


def read_regular_utf8(path: str | Path, *, max_bytes: int = MAX_INPUT_BYTES) -> str:
    raw_path = os.fspath(path)
    st = os.lstat(raw_path)
    if stat.S_ISLNK(st.st_mode):
        raise ContractError("symlink JSON input is forbidden")
    if not stat.S_ISREG(st.st_mode):
        raise ContractError("JSON input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise ContractError("symlink JSON input is forbidden") from err
        raise
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (st.st_dev, st.st_ino) != (fst.st_dev, fst.st_ino):
            raise ContractError("JSON input must be an unchanged regular file")
        if fst.st_size > max_bytes:
            raise ContractError("JSON input exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ContractError("JSON input exceeds maximum size")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ContractError("invalid UTF-8 JSON input") from err


def strict_loads(raw: str) -> Any:
    if not isinstance(raw, str):
        raise ContractError("JSON input must be text")
    if len(raw.encode("utf-8", errors="surrogatepass")) > MAX_INPUT_BYTES:
        raise ContractError("JSON input exceeds maximum size")

    def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if not isinstance(key, str):
                raise ContractError("JSON object key must be a string")
            if key in obj:
                raise ContractError("duplicate JSON key")
            obj[key] = val
        return obj

    def _reject_constant(token: str) -> Any:
        raise ContractError("non-finite JSON constant is forbidden")

    def _parse_finite_float(token: str) -> float:
        parsed = float(token)
        if not math.isfinite(parsed):
            raise ContractError("JSON float out of finite IEEE-754 range")
        return parsed

    try:
        data = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except ContractError:
        raise
    except RecursionError as err:
        raise ContractError("JSON nesting depth exceeded") from err
    _enforce_json_bounds(data)
    return data


def canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
                if not isinstance(key, str):
                    raise ContractError("JSON object key must be a string")
                if SENSITIVE.search(key) and key not in SAFE_ASSERTIONS:
                    raise ContractError("sensitive data channel")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str) and SECRET_MATERIAL.search(current):
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
        self.patterns = {name: re.compile(defs[name]["pattern"]) for name in names}
        self.max_lengths = {
            name: defs[name]["maxLength"] for name in names if "maxLength" in defs[name]
        }

    def ref(self, name: str, value: Any) -> str:
        max_len = self.max_lengths.get(name)
        if (
            not isinstance(value, str)
            or (max_len is not None and len(value) > max_len)
            or self.patterns[name].fullmatch(value) is None
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
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                raise ContractError("open object schema")
            for child in value.values():
                self._closed(child)
        elif isinstance(value, list):
            for child in value:
                self._closed(child)
