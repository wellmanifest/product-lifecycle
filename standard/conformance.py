#!/usr/bin/env python3
"""Dependency-free conformance checks for product lifecycle v1."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import product_fixtures as _fx  # noqa: E402
from product_primitives import (  # noqa: E402
    ALLOWED_OUTCOMES,
    GRAMMAR_DIGEST,
    LIFECYCLE_PROFILE_DIGEST,
    LIFECYCLE_SOURCE_REVISION,
    LIFECYCLE_TRANSITIONS,
    LIFECYCLE_VALIDATOR_DIGESTS,
    SCHEMA_DIGEST,
    SCHEMA_URI,
    SEMVER_RE,
    STAGES,
    ContractError,
    Contracts,
    bounded_int,
    bounded_list,
    canonical,
    digest,
    enum_str,
    exact,
    file_digest,
    iso_date_value,
    read_regular_utf8,
    reject_sensitive,
    strict_bool,
    strict_loads,
    time_value,
    unique_list,
    validate_lifecycle_profile,
)

catalog_example, request_example = _fx.catalog_example, _fx.request_example
lifecycle_example, receipt_example = _fx.lifecycle_example, _fx.receipt_example

__all__ = [
    "ContractError",
    "Contracts",
    "GRAMMAR_DIGEST",
    "LIFECYCLE_PROFILE_DIGEST",
    "LIFECYCLE_SOURCE_REVISION",
    "LIFECYCLE_TRANSITIONS",
    "LIFECYCLE_VALIDATOR_DIGESTS",
    "SCHEMA_DIGEST",
    "SCHEMA_URI",
    "STAGES",
    "canonical",
    "catalog_example",
    "digest",
    "file_digest",
    "lifecycle_example",
    "main",
    "read_regular_utf8",
    "receipt_example",
    "request_example",
    "run_all",
    "strict_loads",
    "validate_availability",
    "validate_catalog",
    "validate_document",
    "validate_lifecycle",
    "validate_lifecycle_profile",
    "validate_product",
    "validate_receipt",
    "validate_request",
]

_AVAILABILITY_STATUS = {"offered", "restricted", "prohibited"}
_PRODUCT_KINDS = {"software", "saas", "service", "hardware", "content", "mixed"}
_OPERATIONS = {
    "inspect",
    "register",
    "release",
    "restrict",
    "deprecate",
    "withdraw",
    "sunset",
}


def validate_availability(c: Contracts, items: Any) -> list[dict[str, Any]]:
    entries = bounded_list(items, "invalid availability", minimum=1, maximum=64)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in entries:
        item = exact(item, {"jurisdictionRef", "status"})
        ref = c.ref("jurisdictionRef", item["jurisdictionRef"])
        if ref in seen:
            raise ContractError("duplicate availability")
        seen.add(ref)
        enum_str(item["status"], _AVAILABILITY_STATUS, "invalid availability status")
        out.append(item)
    return out


def validate_product(c: Contracts, value: Any) -> None:
    value = exact(
        value,
        {
            "ref",
            "name",
            "kind",
            "stage",
            "licenseRef",
            "legalPackRef",
            "availability",
            "entitlements",
            "public",
        },
        {"successorProductRef"},
    )
    c.ref("productRef", value["ref"])
    if not isinstance(value["name"], str) or not 1 <= len(value["name"]) <= 120:
        raise ContractError("invalid product name")
    enum_str(value["kind"], _PRODUCT_KINDS, "invalid product kind")
    stage = enum_str(value["stage"], STAGES, "invalid product stage")
    c.ref("licenseRef", value["licenseRef"])
    c.ref("packRef", value["legalPackRef"])
    availability = validate_availability(c, value["availability"])
    for entitlement in unique_list(
        value["entitlements"], "invalid entitlements", minimum=1, maximum=64
    ):
        c.ref("entitlementRef", entitlement)
    is_public = strict_bool(value["public"], "invalid public flag")
    if is_public and stage == "draft":
        raise ContractError("draft product cannot be public")
    if stage in {"generally-available", "restricted"} and not any(
        item["status"] == "offered" for item in availability
    ):
        raise ContractError("released product has no offered jurisdiction")
    if "successorProductRef" in value and (
        c.ref("productRef", value["successorProductRef"]) == value["ref"]
    ):
        raise ContractError("product cannot succeed itself")


def validate_catalog(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(
        value,
        {"$schema", "schema", "catalogId", "version", "products", "defaultLegalPackRef"},
    )
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.product-catalog/v1":
        raise ContractError("unsupported catalog")
    c.ref("identifier", value["catalogId"])
    if not isinstance(value["version"], str) or SEMVER_RE.fullmatch(value["version"]) is None:
        raise ContractError("invalid catalog version")
    c.ref("packRef", value["defaultLegalPackRef"])
    seen: set[str] = set()
    for item in bounded_list(value["products"], "invalid products", minimum=1, maximum=64):
        validate_product(c, item)
        ref = item["ref"]
        if ref in seen:
            raise ContractError("duplicate product")
        seen.add(ref)


def validate_request(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(
        value,
        {
            "$schema",
            "schema",
            "requestId",
            "operation",
            "catalogRef",
            "productRef",
            "legalPackRef",
            "intentRef",
            "grantRef",
            "planHash",
        },
    )
    if (
        value["$schema"] != SCHEMA_URI
        or value["schema"] != "wellmanifest.product-lifecycle-request/v1"
    ):
        raise ContractError("unsupported request")
    c.ref("identifier", value["requestId"])
    enum_str(value["operation"], _OPERATIONS, "unsupported operation")
    for name in ("catalogRef", "productRef", "packRef", "intentRef", "grantRef"):
        key = "legalPackRef" if name == "packRef" else name
        c.ref(name, value[key])
    c.ref("sha256", value["planHash"])


def validate_lifecycle(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(
        value,
        {
            "$schema",
            "schema",
            "catalogRef",
            "productRef",
            "stage",
            "version",
            "updatedAt",
            "availability",
        },
        {"successorProductRef", "sunsetAt"},
    )
    if (
        value["$schema"] != SCHEMA_URI
        or value["schema"] != "wellmanifest.product-lifecycle-state/v1"
    ):
        raise ContractError("unsupported state")
    c.ref("catalogRef", value["catalogRef"])
    c.ref("productRef", value["productRef"])
    stage = enum_str(value["stage"], STAGES, "invalid stage")
    bounded_int(value["version"], 1, 2_147_483_647, "invalid version")
    time_value(value["updatedAt"])
    availability = validate_availability(c, value["availability"])
    if stage in {"generally-available", "restricted"} and not any(
        item["status"] == "offered" for item in availability
    ):
        raise ContractError("active product has no offered jurisdiction")
    if "sunsetAt" in value:
        iso_date_value(value["sunsetAt"])
    elif stage == "sunset":
        raise ContractError("sunset state missing date")
    if "successorProductRef" in value and (
        c.ref("productRef", value["successorProductRef"]) == value["productRef"]
    ):
        raise ContractError("product cannot succeed itself")


def validate_receipt(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(
        value,
        {
            "$schema",
            "schema",
            "requestId",
            "catalogRef",
            "productRef",
            "inputHash",
            "planHash",
            "outcome",
            "startedAt",
            "completedAt",
            "evidenceRefs",
            "secretsRedacted",
            "commercialDataStored",
        },
    )
    if (
        value["$schema"] != SCHEMA_URI
        or value["schema"] != "wellmanifest.product-lifecycle-receipt/v1"
    ):
        raise ContractError("unsupported receipt")
    c.ref("identifier", value["requestId"])
    c.ref("catalogRef", value["catalogRef"])
    c.ref("productRef", value["productRef"])
    c.ref("sha256", value["inputHash"])
    c.ref("sha256", value["planHash"])
    enum_str(value["outcome"], ALLOWED_OUTCOMES, "invalid outcome")
    if time_value(value["completedAt"]) < time_value(value["startedAt"]):
        raise ContractError("receipt chronology")
    for ref in unique_list(value["evidenceRefs"], "invalid evidenceRefs", minimum=1, maximum=64):
        c.ref("evidenceRef", ref)
    if value["secretsRedacted"] is not True or value["commercialDataStored"] is not False:
        raise ContractError("unsafe receipt")


def validate_document(value: Any) -> None:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    schema_id = value.get("schema")
    if not isinstance(schema_id, str):
        raise ContractError("unsupported document schema")
    c = Contracts()
    c.integrity()
    dispatch = {
        "wellmanifest.product-catalog/v1": validate_catalog,
        "wellmanifest.product-lifecycle-request/v1": validate_request,
        "wellmanifest.product-lifecycle-state/v1": validate_lifecycle,
        "wellmanifest.product-lifecycle-receipt/v1": validate_receipt,
    }
    validator = dispatch.get(schema_id)
    if validator is None:
        raise ContractError("unsupported document schema")
    validator(c, value)


def run_all() -> dict[str, Any]:
    c = Contracts()
    c.integrity()
    validate_lifecycle_profile(c.schema)
    validate_catalog(c, catalog_example())
    validate_request(c, request_example())
    validate_lifecycle(c, lifecycle_example())
    validate_receipt(c, receipt_example())
    cases = _fx.build_adversarial_cases(
        validate_catalog_fn=lambda d: validate_catalog(c, d),
        validate_request_fn=lambda d: validate_request(c, d),
        validate_lifecycle_fn=lambda d: validate_lifecycle(c, d),
        validate_receipt_fn=lambda d: validate_receipt(c, d),
        strict_loads_fn=strict_loads,
    )
    rejected: list[str] = []
    for name, case in cases:
        try:
            case()
        except ContractError:
            rejected.append(name)
        else:
            raise AssertionError(f"adversarial case accepted: {name}")
    return {
        "schema": "wellmanifest.product-lifecycle-conformance/v1",
        "ok": True,
        "schemaDigest": "sha256:" + SCHEMA_DIGEST,
        "grammarDigest": "sha256:" + GRAMMAR_DIGEST,
        "lifecycleSourceRevision": LIFECYCLE_SOURCE_REVISION,
        "positiveVariants": 4,
        "adversarialRejected": rejected,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.all:
            print(json.dumps(run_all(), indent=2, sort_keys=True, allow_nan=False))
        elif args.file:
            target = Path(os.path.abspath(os.fspath(args.file)))
            validate_document(strict_loads(read_regular_utf8(target)))
            print(f"PASS: {args.file}")
        else:
            parser.error("choose --all or --file")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
