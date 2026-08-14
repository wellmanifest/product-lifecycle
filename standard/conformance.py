#!/usr/bin/env python3
"""Dependency-free conformance checks for product lifecycle v1."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any

import lifecycle


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "product-lifecycle.schema.json"
GRAMMAR_PATH = ROOT / "product-lifecycle.v1.gbnf"
LIFECYCLE_PATH = ROOT / "product-lifecycle.lifecycle"
LIFECYCLE_VALIDATOR_PATH = ROOT / "lifecycle.py"
SCHEMA_DIGEST = "d80ab5ddb5e3393f83261c29f53ad4e60be4855f3d5d8f6d1d1dd6dd5f8b87c6"
GRAMMAR_DIGEST = "f54372cd1e613b3d120a577987937fc7e3cc7dd795a246ecffad155d16e32f56"
LIFECYCLE_SOURCE_REVISION = "4b5e131a670afb46ca87291479fed7c0fefcf370"
LIFECYCLE_VALIDATOR_DIGEST = "9c3f3076b5b45408d3eefc34cd567b58821aa565d3fe3bf6339641111079ede0"
LIFECYCLE_PROFILE_DIGEST = "7b95f50fac0ce58c957e83159d4f86693ac366b9c52d9e0c3b8240ec3ae61bde"
SCHEMA_URI = "https://wellmanifest.dev/schemas/product-lifecycle/v1"
SENSITIVE = re.compile(
    r"(?:password|passwd|token|secret|cookie|api[-_]?key|card|cvv|private[-_]?key|"
    r"price|amount|currency|settlement|hostname|ssh|docroot|marketing[-_]?copy)",
    re.I,
)
SAFE_ASSERTIONS = {"secretsRedacted", "commercialDataStored"}
STAGES = {"draft", "preview", "generally-available", "restricted", "deprecated", "withdrawn", "sunset"}
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


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lifecycle_name(value: str) -> str:
    return value.upper().replace("-", "_")


def validate_lifecycle_profile(schema: dict[str, Any]) -> None:
    if file_digest(LIFECYCLE_VALIDATOR_PATH) != LIFECYCLE_VALIDATOR_DIGEST:
        raise ContractError("pinned lifecycle validator digest mismatch")
    if file_digest(LIFECYCLE_PATH) != LIFECYCLE_PROFILE_DIGEST:
        raise ContractError("pinned lifecycle profile digest mismatch")
    report = lifecycle.validate_path(LIFECYCLE_PATH, lifecycle.embedded_catalog())
    if not report.valid or len(report.lifecycles) != 1:
        raise ContractError("Lifecycle DSL profile is invalid")
    model = report.lifecycles[0]
    state_values = schema["$defs"]["stage"]["enum"]
    expected_states = {lifecycle_name(str(value)) for value in state_values}
    actual_transitions = {
        (item.source, item.target, item.event) for item in model.transitions
    }
    if model.name != "product-release" or set(model.states) != expected_states:
        raise ContractError("Lifecycle DSL state graph mismatch")
    if actual_transitions != LIFECYCLE_TRANSITIONS:
        raise ContractError("Lifecycle DSL transition graph mismatch")
    if model.summary()["initial_state"] != "DRAFT":
        raise ContractError("Lifecycle DSL initial state mismatch")
    if model.summary()["terminal_states"] != ["SUNSET"]:
        raise ContractError("Lifecycle DSL terminal state mismatch")


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    optional = optional or set()
    if set(value) - required - optional:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing field")
    return value


def time_value(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ContractError("invalid date-time")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("invalid date-time") from error
    if result.tzinfo is None:
        raise ContractError("timezone required")
    return result


def reject_sensitive(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE.search(key) and key not in SAFE_ASSERTIONS:
                raise ContractError("sensitive data channel")
            reject_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive(child)


class Contracts:
    def __init__(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        self.grammar = GRAMMAR_PATH.read_text("utf-8")
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

    def ref(self, name: str, value: Any) -> str:
        if not isinstance(value, str) or self.patterns[name].fullmatch(value) is None:
            raise ContractError(f"invalid {name}")
        return value

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or self.schema.get("$id") != SCHEMA_URI:
            raise ContractError("schema identity mismatch")
        if digest(canonical(self.schema)) != SCHEMA_DIGEST or digest(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("contract digest mismatch")
        if {x.get("$ref") for x in self.schema.get("oneOf", [])} != {
            "#/$defs/catalog",
            "#/$defs/request",
            "#/$defs/lifecycle",
            "#/$defs/receipt",
        }:
            raise ContractError("document variants incomplete")
        for fragment in ("root ::= request", "marketing copy", "product-ref ::=", "catalog-ref ::=", "sha256 ::="):
            if fragment not in self.grammar:
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


def catalog_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.product-catalog/v1",
        "catalogId": "catalog-2026-08",
        "version": "1.0.0",
        "products": [
            {
                "ref": "product://example.test/subactor/v1",
                "name": "Subactor",
                "kind": "saas",
                "stage": "generally-available",
                "licenseRef": "license://example.test/proprietary/v1",
                "legalPackRef": "pack://example.test/saas/legal/v1",
                "availability": [
                    {"jurisdictionRef": "jurisdiction://example.test/eu-pl/v1", "status": "offered"},
                    {"jurisdictionRef": "jurisdiction://example.test/us-ca/v1", "status": "restricted"},
                ],
                "entitlements": ["entitlement://example.test/subactor/starter/v1"],
                "public": True,
            }
        ],
        "defaultLegalPackRef": "pack://example.test/saas/legal/v1",
    }


def request_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.product-lifecycle-request/v1",
        "requestId": "request-001",
        "operation": "release",
        "catalogRef": "catalog://example.test/public/v1",
        "productRef": "product://example.test/subactor/v1",
        "legalPackRef": "pack://example.test/saas/legal/v1",
        "intentRef": "intent://example.test/product/request-001",
        "grantRef": "grant://example.test/product/request-001/g1",
        "planHash": "a" * 64,
    }


def lifecycle_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.product-lifecycle-state/v1",
        "catalogRef": "catalog://example.test/public/v1",
        "productRef": "product://example.test/subactor/v1",
        "stage": "generally-available",
        "version": 4,
        "updatedAt": "2026-08-13T12:00:00Z",
        "availability": [
            {"jurisdictionRef": "jurisdiction://example.test/eu-pl/v1", "status": "offered"}
        ],
    }


def receipt_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.product-lifecycle-receipt/v1",
        "requestId": "request-001",
        "catalogRef": "catalog://example.test/public/v1",
        "productRef": "product://example.test/subactor/v1",
        "inputHash": "c" * 64,
        "planHash": "a" * 64,
        "outcome": "released",
        "startedAt": "2026-08-13T11:50:00Z",
        "completedAt": "2026-08-13T12:00:00Z",
        "evidenceRefs": ["evidence://example.test/product/release-001/r1"],
        "secretsRedacted": True,
        "commercialDataStored": False,
    }


def validate_availability(c: Contracts, items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise ContractError("availability missing")
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        item = exact(item, {"jurisdictionRef", "status"})
        ref = c.ref("jurisdictionRef", item["jurisdictionRef"])
        if ref in seen:
            raise ContractError("duplicate availability")
        seen.add(ref)
        if item["status"] not in {"offered", "restricted", "prohibited"}:
            raise ContractError("invalid availability status")
        out.append(item)
    return out


def validate_product(c: Contracts, value: Any) -> None:
    value = exact(
        value,
        {"ref", "name", "kind", "stage", "licenseRef", "legalPackRef", "availability", "entitlements", "public"},
        {"successorProductRef"},
    )
    c.ref("productRef", value["ref"])
    if not isinstance(value["name"], str) or not 1 <= len(value["name"]) <= 120:
        raise ContractError("invalid product name")
    if value["kind"] not in {"software", "saas", "service", "hardware", "content", "mixed"}:
        raise ContractError("invalid product kind")
    if value["stage"] not in STAGES:
        raise ContractError("invalid product stage")
    c.ref("licenseRef", value["licenseRef"])
    c.ref("packRef", value["legalPackRef"])
    availability = validate_availability(c, value["availability"])
    if not value["entitlements"]:
        raise ContractError("product without entitlements")
    for entitlement in value["entitlements"]:
        c.ref("entitlementRef", entitlement)
    if value["public"] is True and value["stage"] == "draft":
        raise ContractError("draft product cannot be public")
    if value["stage"] in {"generally-available", "restricted"} and not any(
        item["status"] == "offered" for item in availability
    ):
        raise ContractError("released product has no offered jurisdiction")
    if value["stage"] == "sunset" and "successorProductRef" not in value:
        pass
    if "successorProductRef" in value:
        if c.ref("productRef", value["successorProductRef"]) == value["ref"]:
            raise ContractError("product cannot succeed itself")


def validate_catalog(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(value, {"$schema", "schema", "catalogId", "version", "products", "defaultLegalPackRef"})
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.product-catalog/v1":
        raise ContractError("unsupported catalog")
    c.ref("identifier", value["catalogId"])
    c.ref("packRef", value["defaultLegalPackRef"])
    seen: set[str] = set()
    for item in value["products"]:
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
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.product-lifecycle-request/v1":
        raise ContractError("unsupported request")
    c.ref("identifier", value["requestId"])
    if value["operation"] not in {"inspect", "register", "release", "restrict", "deprecate", "withdraw", "sunset"}:
        raise ContractError("unsupported operation")
    for name in ("catalogRef", "productRef", "packRef", "intentRef", "grantRef"):
        key = "legalPackRef" if name == "packRef" else name
        c.ref(name if name != "packRef" else "packRef", value[key])
    c.ref("sha256", value["planHash"])


def validate_lifecycle(c: Contracts, value: Any) -> None:
    reject_sensitive(value)
    value = exact(
        value,
        {"$schema", "schema", "catalogRef", "productRef", "stage", "version", "updatedAt", "availability"},
        {"successorProductRef", "sunsetAt"},
    )
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.product-lifecycle-state/v1":
        raise ContractError("unsupported state")
    c.ref("catalogRef", value["catalogRef"])
    c.ref("productRef", value["productRef"])
    if value["stage"] not in STAGES:
        raise ContractError("invalid stage")
    if not isinstance(value["version"], int) or value["version"] < 1:
        raise ContractError("invalid version")
    time_value(value["updatedAt"])
    availability = validate_availability(c, value["availability"])
    if value["stage"] in {"generally-available", "restricted"} and not any(
        item["status"] == "offered" for item in availability
    ):
        raise ContractError("active product has no offered jurisdiction")
    if value["stage"] == "sunset":
        if "sunsetAt" not in value:
            raise ContractError("sunset state missing date")
        try:
            date.fromisoformat(value["sunsetAt"])
        except (TypeError, ValueError) as error:
            raise ContractError("invalid sunset date") from error
    if "successorProductRef" in value:
        if c.ref("productRef", value["successorProductRef"]) == value["productRef"]:
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
    if value["$schema"] != SCHEMA_URI or value["schema"] != "wellmanifest.product-lifecycle-receipt/v1":
        raise ContractError("unsupported receipt")
    c.ref("identifier", value["requestId"])
    c.ref("catalogRef", value["catalogRef"])
    c.ref("productRef", value["productRef"])
    c.ref("sha256", value["inputHash"])
    c.ref("sha256", value["planHash"])
    if time_value(value["completedAt"]) < time_value(value["startedAt"]):
        raise ContractError("receipt chronology")
    if not value["evidenceRefs"]:
        raise ContractError("receipt lacks evidence")
    for ref in value["evidenceRefs"]:
        c.ref("evidenceRef", ref)
    if value["secretsRedacted"] is not True or value["commercialDataStored"] is not False:
        raise ContractError("unsafe receipt")


def run_all() -> dict[str, Any]:
    c = Contracts()
    c.integrity()
    validate_lifecycle_profile(c.schema)
    catalog, request, state, receipt = catalog_example(), request_example(), lifecycle_example(), receipt_example()
    validate_catalog(c, catalog)
    validate_request(c, request)
    validate_lifecycle(c, state)
    validate_receipt(c, receipt)
    cases = []
    bad = copy.deepcopy(catalog)
    bad["products"][0]["stage"] = "draft"
    cases.append(("public-draft", lambda: validate_catalog(c, bad)))
    bad = copy.deepcopy(catalog)
    bad["products"][0]["availability"][0]["status"] = "prohibited"
    bad["products"][0]["availability"][1]["status"] = "prohibited"
    cases.append(("ga-without-offered-jurisdiction", lambda: validate_catalog(c, bad)))
    bad = copy.deepcopy(catalog)
    bad["products"][0]["successorProductRef"] = bad["products"][0]["ref"]
    cases.append(("self-successor", lambda: validate_catalog(c, bad)))
    bad = copy.deepcopy(request)
    bad["price"] = 49
    cases.append(("inline-price", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request)
    bad["hostname"] = "acme.example.test"
    cases.append(("raw-hostname", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(request)
    bad["settlement"] = {"currency": "EUR"}
    cases.append(("commercial-settlement", lambda: validate_request(c, bad)))
    bad = copy.deepcopy(state)
    bad["stage"] = "sunset"
    cases.append(("sunset-without-date", lambda: validate_lifecycle(c, bad)))
    bad = copy.deepcopy(state)
    bad["availability"][0]["status"] = "prohibited"
    cases.append(("active-without-offer", lambda: validate_lifecycle(c, bad)))
    bad = copy.deepcopy(receipt)
    bad["commercialDataStored"] = True
    cases.append(("commercial-data-receipt", lambda: validate_receipt(c, bad)))
    bad = copy.deepcopy(receipt)
    bad["marketingCopy"] = "best saas ever"
    cases.append(("marketing-copy-receipt", lambda: validate_receipt(c, bad)))
    rejected = []
    for name, case in cases:
        try:
            case()
        except (ContractError, KeyError, TypeError):
            rejected.append(name)
        else:
            raise AssertionError(f"adversarial case accepted: {name}")
    return {
        "schema": "wellmanifest.product-lifecycle-conformance/v1",
        "ok": True,
        "schemaDigest": "sha256:" + SCHEMA_DIGEST,
        "grammarDigest": "sha256:" + GRAMMAR_DIGEST,
        "positiveVariants": 4,
        "adversarialRejected": rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not args.all:
        parser.error("--all is required")
    print(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
