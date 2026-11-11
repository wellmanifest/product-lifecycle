#!/usr/bin/env python3
"""Reference positive and adversarial fixtures for Wellmanifest product-lifecycle v1."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

SCHEMA_URI = "https://wellmanifest.dev/schemas/product-lifecycle/v1"


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
                    {
                        "jurisdictionRef": "jurisdiction://example.test/eu-pl/v1",
                        "status": "offered",
                    },
                    {
                        "jurisdictionRef": "jurisdiction://example.test/us-ca/v1",
                        "status": "restricted",
                    },
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


def build_adversarial_cases(
    *,
    validate_catalog_fn: Callable[[dict[str, Any]], None],
    validate_request_fn: Callable[[dict[str, Any]], None],
    validate_lifecycle_fn: Callable[[dict[str, Any]], None],
    validate_receipt_fn: Callable[[dict[str, Any]], None],
    strict_loads_fn: Callable[[str], Any],
) -> list[tuple[str, Callable[[], Any]]]:
    catalog = catalog_example()
    request = request_example()
    state = lifecycle_example()
    receipt = receipt_example()
    cases: list[tuple[str, Callable[[], Any]]] = []

    def _add(
        name: str,
        base: dict[str, Any],
        mutator: Callable[[dict[str, Any]], None],
        fn: Callable[[dict[str, Any]], None],
    ) -> None:
        doc = copy.deepcopy(base)
        mutator(doc)
        cases.append((name, lambda d=doc, f=fn: f(d)))

    _add(
        "public-draft",
        catalog,
        lambda d: d["products"][0].__setitem__("stage", "draft"),
        validate_catalog_fn,
    )
    _add(
        "ga-without-offered-jurisdiction",
        catalog,
        lambda d: (
            d["products"][0]["availability"][0].__setitem__("status", "prohibited"),
            d["products"][0]["availability"][1].__setitem__("status", "prohibited"),
        ),
        validate_catalog_fn,
    )
    _add(
        "self-successor",
        catalog,
        lambda d: d["products"][0].__setitem__("successorProductRef", d["products"][0]["ref"]),
        validate_catalog_fn,
    )
    _add(
        "invalid-catalog-semver",
        catalog,
        lambda d: d.__setitem__("version", "v1"),
        validate_catalog_fn,
    )
    _add(
        "empty-catalog-products",
        catalog,
        lambda d: d.__setitem__("products", []),
        validate_catalog_fn,
    )
    _add(
        "non-bool-product-public",
        catalog,
        lambda d: d["products"][0].__setitem__("public", "false"),
        validate_catalog_fn,
    )
    _add(
        "duplicate-product-entitlements",
        catalog,
        lambda d: d["products"][0].__setitem__(
            "entitlements",
            [
                "entitlement://example.test/subactor/starter/v1",
                "entitlement://example.test/subactor/starter/v1",
            ],
        ),
        validate_catalog_fn,
    )
    _add(
        "unhashable-product-entitlement",
        catalog,
        lambda d: d["products"][0].__setitem__("entitlements", [{"bad": 1}]),
        validate_catalog_fn,
    )
    _add("inline-price", request, lambda d: d.__setitem__("price", 49), validate_request_fn)
    _add(
        "raw-hostname",
        request,
        lambda d: d.__setitem__("hostname", "acme.example.test"),
        validate_request_fn,
    )
    _add(
        "commercial-settlement",
        request,
        lambda d: d.__setitem__("settlement", {"currency": "EUR"}),
        validate_request_fn,
    )
    token = "gh" + "p_" + ("A" * 26)
    _add(
        "inline-secret-material",
        request,
        lambda d: d.__setitem__("intentRef", token),
        validate_request_fn,
    )
    _add(
        "sunset-without-date",
        state,
        lambda d: d.__setitem__("stage", "sunset"),
        validate_lifecycle_fn,
    )
    _add(
        "compact-non-iso-sunset-date",
        state,
        lambda d: (d.__setitem__("stage", "sunset"), d.__setitem__("sunsetAt", "20260813")),
        validate_lifecycle_fn,
    )
    _add(
        "bool-state-version", state, lambda d: d.__setitem__("version", True), validate_lifecycle_fn
    )
    _add(
        "space-datetime-state",
        state,
        lambda d: d.__setitem__("updatedAt", "2026-08-13 12:00:00Z"),
        validate_lifecycle_fn,
    )
    _add(
        "active-without-offer",
        state,
        lambda d: d["availability"][0].__setitem__("status", "prohibited"),
        validate_lifecycle_fn,
    )
    _add(
        "commercial-data-receipt",
        receipt,
        lambda d: d.__setitem__("commercialDataStored", True),
        validate_receipt_fn,
    )
    _add(
        "marketing-copy-receipt",
        receipt,
        lambda d: d.__setitem__("marketingCopy", "best saas ever"),
        validate_receipt_fn,
    )
    _add(
        "invalid-receipt-outcome",
        receipt,
        lambda d: d.__setitem__("outcome", "bogus"),
        validate_receipt_fn,
    )
    _add(
        "duplicate-receipt-evidence",
        receipt,
        lambda d: d.__setitem__(
            "evidenceRefs",
            [
                "evidence://example.test/product/release-001/r1",
                "evidence://example.test/product/release-001/r1",
            ],
        ),
        validate_receipt_fn,
    )
    cases.append(("duplicate-json-keys", lambda: strict_loads_fn('{"a": 1, "a": 2}')))
    return cases
