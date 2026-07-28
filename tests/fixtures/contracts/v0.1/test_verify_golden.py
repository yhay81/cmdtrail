#!/usr/bin/env python3
"""Exercise the independent verifier against the declared mutation corpus."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import verify_golden

ROOT = pathlib.Path(__file__).parent


def mutate(document: object, operation: str, pointer: str, value: object) -> None:
    parts = [part for part in pointer.split("/") if part]
    target = document
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    key = parts[-1]
    if isinstance(target, list):
        target[int(key)] = value
    elif operation == "add":
        if key in target:
            raise AssertionError(f"add target already exists: {pointer}")
        target[key] = value
    elif operation == "replace":
        if key not in target:
            raise AssertionError(f"replace target is absent: {pointer}")
        target[key] = value
    else:
        raise AssertionError(f"unsupported mutation operation: {operation}")


class CorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = json.loads((ROOT / "portable.receipt.json").read_text())
        cls.manifest = json.loads((ROOT / "manifest.json").read_text())

    def test_golden_receipt_verifies(self) -> None:
        receipt = verify_golden.validate_receipt(copy.deepcopy(self.receipt))
        self.assertEqual(verify_golden.verify(receipt), [])

    def test_declared_mutations_fail_closed(self) -> None:
        ids: set[str] = set()
        for case in self.manifest["rejections"]:
            with self.subTest(case=case["id"]):
                self.assertNotIn(case["id"], ids)
                ids.add(case["id"])
                receipt = copy.deepcopy(self.receipt)
                mutate(
                    receipt,
                    case["operation"],
                    case["pointer"],
                    case["value"],
                )
                if case["class"] == "parse":
                    with self.assertRaises(ValueError):
                        verify_golden.validate_receipt(receipt)
                else:
                    verified = verify_golden.validate_receipt(receipt)
                    self.assertIn(case["expected_error"], verify_golden.verify(verified))
        self.assertEqual(len(ids), 12)


if __name__ == "__main__":
    unittest.main()
