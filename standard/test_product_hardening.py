"""Adversarial hardening suite for product-lifecycle file I/O, JSON bounds, and enum guards."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

import conformance as prod
import product_primitives as pp


class ProductLifecycleHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = prod.Contracts()
        self.contracts.integrity()

    def test_read_regular_utf8_and_cli_reject_symlink_directory_and_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "request.json"
            real.write_text(json.dumps(prod.request_example()), encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)

            with self.assertRaises(prod.ContractError):
                prod.read_regular_utf8(link)
            self.assertEqual(prod.main(["--file", str(link)]), 1)
            self.assertEqual(prod.main(["--file", str(root)]), 1)

            if hasattr(os, "mkfifo"):
                fifo = root / "pipe.json"
                os.mkfifo(fifo)
                with self.assertRaises(prod.ContractError):
                    prod.read_regular_utf8(fifo)
                self.assertEqual(prod.main(["--file", str(fifo)]), 1)

    def test_strict_loads_rejects_nan_infinity_overflow_and_deep_nesting(self) -> None:
        deep = ("[" * (pp.MAX_JSON_DEPTH + 2)) + "1" + ("]" * (pp.MAX_JSON_DEPTH + 2))
        extreme = ("[" * 1500) + "1" + ("]" * 1500)
        for raw in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999", deep, extreme):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(prod.ContractError):
                    prod.strict_loads(raw)

    def test_unhashable_enums_and_non_string_keys_raise_contract_error(self) -> None:
        with self.assertRaises(prod.ContractError):
            prod.validate_document({"schema": ["unhashable"]})

        cat = copy.deepcopy(prod.catalog_example())
        cat["products"][0]["kind"] = ["saas"]
        with self.assertRaises(prod.ContractError):
            prod.validate_catalog(self.contracts, cat)

        cat2 = copy.deepcopy(prod.catalog_example())
        cat2["products"][0]["availability"][0]["status"] = {"bad": 1}
        with self.assertRaises(prod.ContractError):
            prod.validate_catalog(self.contracts, cat2)

        req = copy.deepcopy(prod.request_example())
        req["operation"] = ["inspect"]
        with self.assertRaises(prod.ContractError):
            prod.validate_request(self.contracts, req)

        lfc = copy.deepcopy(prod.lifecycle_example())
        lfc["stage"] = ["draft"]
        with self.assertRaises(prod.ContractError):
            prod.validate_lifecycle(self.contracts, lfc)

        rcpt = copy.deepcopy(prod.receipt_example())
        rcpt["outcome"] = {"bad": 1}
        with self.assertRaises(prod.ContractError):
            prod.validate_receipt(self.contracts, rcpt)

        bad_key_obj = copy.deepcopy(prod.request_example())
        bad_key_obj[99] = "invalid"  # type: ignore[index]
        with self.assertRaises(prod.ContractError):
            prod.validate_request(self.contracts, bad_key_obj)

        nested: object = "safe"
        for _ in range(pp.MAX_JSON_DEPTH + 4):
            nested = {"child": nested}
        with self.assertRaises(prod.ContractError):
            pp.reject_sensitive(nested)


if __name__ == "__main__":
    unittest.main()
