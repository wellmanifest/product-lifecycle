"""Strict external catalog loader for Lifecycle DSL v1 diagnostics."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lifecycle import CatalogEntry

CATALOG_SCHEMA = "lifecycle.diagnostics/v1"
SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}
CORE_CODE = re.compile(r"^LFC-[A-Z]+-[0-9]{3}$")


def load_catalog_impl(path: Path) -> dict[str, CatalogEntry]:
    from lifecycle import REQUIRED_CORE_CODES, CatalogEntry, CatalogError

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if key in obj:
                raise CatalogError(f"LFC-CATALOG-001: duplicate JSON key {key!r}")
            obj[key] = val
        return obj

    try:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw, object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CatalogError(f"LFC-CATALOG-001: cannot load {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "version",
        "diagnostics",
    }:
        raise CatalogError("LFC-CATALOG-001: catalog fields are invalid")
    version = document["version"]
    if document["schema"] != CATALOG_SCHEMA or type(version) is not int or version != 1:
        raise CatalogError("LFC-CATALOG-001: catalog schema or version is unsupported")
    rows = document["diagnostics"]
    if not isinstance(rows, list):
        raise CatalogError("LFC-CATALOG-001: diagnostics must be an array")
    result: dict[str, CatalogEntry] = {}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"code", "severity", "message"}:
            raise CatalogError(f"LFC-CATALOG-001: diagnostic {idx} fields are invalid")
        code, severity, msg = row["code"], row["severity"], row["message"]
        if (
            not isinstance(code, str)
            or CORE_CODE.fullmatch(code) is None
            or not isinstance(severity, str)
            or severity not in SEVERITIES
            or not isinstance(msg, str)
            or not msg.strip()
            or code in result
        ):
            raise CatalogError(f"LFC-CATALOG-001: diagnostic {idx} is invalid")
        result[code] = CatalogEntry(code, severity, msg)
    if set(result) != REQUIRED_CORE_CODES:
        missing = sorted(REQUIRED_CORE_CODES - set(result))
        extra = sorted(set(result) - REQUIRED_CORE_CODES)
        raise CatalogError(
            f"LFC-CATALOG-001: code set differs; missing={missing}, extra={extra}"
        )
    return result
