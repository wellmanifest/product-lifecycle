"""Adversarial hardening suite for product-lifecycle file I/O, JSON bounds, and enum guards."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

import conformance as prod
import product_io as pio
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

    def test_int_overflow_surrogates_secret_keys_ancestor_symlinks_and_ref_bounds(self) -> None:
        for raw in (
            '{"x": ' + "9" * 500 + "}",
            '{"x": -' + "9" * 500 + "}",
            '{"x": ' + "9" * 5000 + "}",
            r'{"x": "\ud800"}',
            r'{"\udfff": 1}',
            '{"x": "\ud800"}',
            "{malformed",
        ):
            with self.subTest(raw=raw[:24]), self.assertRaises(prod.ContractError):
                prod.strict_loads(raw)

        for bad_val in ({"x": 10**400}, {"x": "\ud800"}, {"\ud800": 1}):
            with self.assertRaises(prod.ContractError):
                prod.canonical(bad_val)

        with self.assertRaises(prod.ContractError):
            prod.digest("\ud800")

        canary_key = "gh" + "p_" + ("X9y8Z7" * 5)
        for bad_sensitive in ({canary_key: "v"}, {"\ud800": "v"}, {"safe": "\udfff"}):
            with self.assertRaises(prod.ContractError):
                pp.reject_sensitive(bad_sensitive)

        for bad_ref in (
            ("identifier", "a" * 97),
            ("identifier", "catalog-1\n"),
            ("packRef", "pack://./saas/v1"),
            ("packRef", "pack://../saas/v1"),
            ("packRef", "pack://example.test/../v1"),
            ("packRef", "pack://example.test/./v1"),
            ("packRef", "pack://example.test/a::b/v1"),
            ("packRef", "pack://example.test/a:..:b/v1"),
            ("productRef", "product://example.test/" + "a" * 250 + "/v1"),
        ):
            with self.subTest(ref=bad_ref[1][:32]), self.assertRaises(prod.ContractError):
                self.contracts.ref(bad_ref[0], bad_ref[1])

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real" / "nested"
            real_dir.mkdir(parents=True)
            doc_path = real_dir / "req.json"
            doc_path.write_text(json.dumps(prod.request_example()), encoding="utf-8")

            for bad_max in (0, -1, True, False):
                with self.assertRaises(prod.ContractError):
                    prod.read_regular_utf8(doc_path, max_bytes=bad_max)  # type: ignore[arg-type]

            sym_dir = base / "sym_dir"
            sym_dir.symlink_to(base / "real")
            deep_sym = sym_dir / "nested" / "req.json"
            with self.assertRaises(prod.ContractError):
                prod.read_regular_utf8(deep_sym)
            with self.assertRaises(prod.ContractError):
                prod.file_digest(deep_sym)
            self.assertEqual(prod.main(["--file", str(deep_sym)]), 1)

    def test_cli_dotdot_symlink_traversal_schema_depth_product_names_and_line_budget(self) -> None:
        for bad_int in ('{"x": ' + "9" * 401 + "}", '{"x": -' + "1" + "0" * 400 + "}"):
            with self.assertRaises(prod.ContractError):
                pio.strict_loads(bad_int)

        deep_schema: object = {"type": "string"}
        for _ in range(pio.MAX_JSON_DEPTH + 4):
            deep_schema = {"type": "object", "additionalProperties": False, "items": deep_schema}
        with self.assertRaises(prod.ContractError):
            self.contracts._closed(deep_schema)

        for bad_name in ("   ", "prod\nname", "prod\x00name", "prod\x7f", "prod\ud800"):
            cat = copy.deepcopy(prod.catalog_example())
            cat["products"][0]["name"] = bad_name
            with self.assertRaises(prod.ContractError):
                prod.validate_catalog(self.contracts, cat)

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_dir = base / "real" / "nested"
            real_dir.mkdir(parents=True)
            sibling = base / "sibling"
            sibling.mkdir()
            req_path = real_dir / "req.json"
            req_path.write_text(json.dumps(prod.request_example()), encoding="utf-8")
            (base / "sym_dir").symlink_to(base / "real")

            unnorm_abs = Path(f"{base}/sym_dir/../real/nested/req.json")
            with self.assertRaises(prod.ContractError):
                pio.read_regular_utf8(unnorm_abs)
            self.assertEqual(prod.main(["--file", str(unnorm_abs)]), 1)

            prev_cwd = Path.cwd()
            try:
                os.chdir(base)
                with self.assertRaises(prod.ContractError):
                    pio.read_regular_utf8(Path("sym_dir/../real/nested/req.json"))
                self.assertEqual(prod.main(["--file", "sym_dir/../real/nested/req.json"]), 1)
                os.chdir(sibling)
                with self.assertRaises(prod.ContractError):
                    pio.read_regular_utf8(Path("../sym_dir/nested/req.json"))
                self.assertEqual(prod.main(["--file", "../sym_dir/nested/req.json"]), 1)
            finally:
                os.chdir(prev_cwd)

        for py_file in sorted([*pp.ROOT.glob("*.py"), *(pp.ROOT.parent / "tests").glob("*.py")]):
            lines = len(py_file.read_text(encoding="utf-8").splitlines())
            self.assertLess(lines, 500, f"{py_file} has {lines} lines")


if __name__ == "__main__":
    unittest.main()
