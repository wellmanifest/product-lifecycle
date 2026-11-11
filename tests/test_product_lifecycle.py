"""Pytest/unittest conformance suite for product-lifecycle v1."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDARD_DIR = ROOT / "standard"
if str(STANDARD_DIR) not in sys.path:
    sys.path.insert(0, str(STANDARD_DIR))

import conformance as prod  # noqa: E402


class ProductLifecycleConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = prod.Contracts()
        self.contracts.integrity()

    def test_run_all_conformance_and_lifecycle_profile(self) -> None:
        report = prod.run_all()
        self.assertTrue(report["ok"])
        self.assertEqual(report["schema"], "wellmanifest.product-lifecycle-conformance/v1")
        self.assertEqual(report["positiveVariants"], 4)
        self.assertGreaterEqual(len(report["adversarialRejected"]), 20)

    def test_strict_loads_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(prod.ContractError):
            prod.strict_loads('{"schema":"a","schema":"b"}')

    def test_catalog_and_product_schema_parity(self) -> None:
        cat = copy.deepcopy(prod.catalog_example())
        cat["version"] = "not-semver"
        with self.assertRaises(prod.ContractError):
            prod.validate_catalog(self.contracts, cat)

        cat = copy.deepcopy(prod.catalog_example())
        cat["products"][0]["public"] = "false"
        with self.assertRaises(prod.ContractError):
            prod.validate_catalog(self.contracts, cat)

        cat = copy.deepcopy(prod.catalog_example())
        cat["products"][0]["entitlements"] = [{"unhashable": 1}]
        with self.assertRaises(prod.ContractError):
            prod.validate_catalog(self.contracts, cat)

    def test_state_receipt_and_secret_scanning(self) -> None:
        state = copy.deepcopy(prod.lifecycle_example())
        state["version"] = True
        with self.assertRaises(prod.ContractError):
            prod.validate_lifecycle(self.contracts, state)

        state = copy.deepcopy(prod.lifecycle_example())
        state["stage"] = "sunset"
        state["sunsetAt"] = "20260813"
        with self.assertRaises(prod.ContractError):
            prod.validate_lifecycle(self.contracts, state)

        receipt = copy.deepcopy(prod.receipt_example())
        receipt["outcome"] = "invalid-outcome"
        with self.assertRaises(prod.ContractError):
            prod.validate_receipt(self.contracts, receipt)

        req = copy.deepcopy(prod.request_example())
        req["intentRef"] = "gh" + "p_" + ("A" * 26)
        with self.assertRaises(prod.ContractError):
            prod.validate_request(self.contracts, req)

    def test_cli_file_validation_and_duplicate_key_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            valid_path = Path(tmp) / "request.json"
            valid_path.write_text(json.dumps(prod.request_example()), encoding="utf-8")
            self.assertEqual(prod.main(["--file", str(valid_path)]), 0)

            dup_path = Path(tmp) / "dup.json"
            dup_path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            self.assertEqual(prod.main(["--file", str(dup_path)]), 1)


if __name__ == "__main__":
    unittest.main()
