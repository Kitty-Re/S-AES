import csv
import hashlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.verify_cross_test import ARCHIVE_NAME, SOURCE, read_source_bytes, run_bundle, verify_manifest


class PeerCrossTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary, cls.rows = run_bundle()

    def test_original_archive_and_manifest_remain_identical(self):
        hashes = verify_manifest(SOURCE)
        self.assertEqual(len(hashes), 13)
        archive_path = SOURCE.parent / "S-AES-cross-test-20261024.zip"
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                         "b57ef988afaa6f38a4e14fefb01ab25917646be177980e7019e2cff2fe60209d")
        with zipfile.ZipFile(archive_path) as archive:
            for item in archive.infolist():
                if not item.is_dir():
                    self.assertEqual(archive.read(item), read_source_bytes(SOURCE, Path(item.filename).name))

    def test_all_peer_basic_encryption_and_decryption(self):
        rows = [row for row in self.rows if row["feature"] == "basic"]
        self.assertEqual(len(rows), 128)
        self.assertTrue(all(row["status"] == "PASS" for row in rows))
        self.assertEqual(self.summary["basic_passed"], 64)

    def test_all_peer_extended_modes_tampering_and_invalid_inputs(self):
        self.assertEqual(self.summary["case_total"], 119)
        self.assertEqual(self.summary["passed"], 220)
        self.assertEqual(self.summary["failed"], 0)
        for feature in ("ascii", "double", "triple48", "cbc", "tamper", "invalid"):
            self.assertTrue(all(row["status"] == "PASS" for row in self.rows if row["feature"] == feature))

    def test_full_mitm_candidate_sets_match_external_hashes(self):
        vectors = json.loads((SOURCE / "05_mitm.json").read_text(encoding="utf-8-sig"))
        for case in vectors:
            result = self.summary["mitm"][case["id"]]
            self.assertEqual(result["candidate_count"], case["expected_candidate_count"])
            self.assertEqual(result["candidate_set_sha256"], case["candidate_set_sha256"])
            self.assertTrue(result["completed"])
            self.assertEqual(result["checked"], 131072)

    def test_template_expectations_and_empty_outputs_are_preserved(self):
        with io.StringIO(read_source_bytes(SOURCE, "09_results_template.csv").decode("utf-8-sig"), newline="") as stream:
            template = list(csv.DictReader(stream))
        self.assertEqual([(row["case_id"], row["direction"], row["expected_hex_or_text"]) for row in self.rows],
                         [(row["case_id"], row["direction"], row["expected_hex_or_text"]) for row in template])
        for case_id in ("A001", "C006"):
            row = next(row for row in self.rows if row["case_id"] == case_id and row["direction"] == "decrypt")
            self.assertEqual(row["actual_hex_or_text"], "")
            self.assertEqual(row["status"], "PASS")

    def test_modified_source_is_rejected_and_wrong_computation_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "peer-original"
            shutil.copytree(SOURCE, source)
            shutil.copyfile(SOURCE.parent / ARCHIVE_NAME, source.parent / ARCHIVE_NAME)
            (source / "01_basic.csv").write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_manifest(source)
        with patch("tools.verify_cross_test.encrypt_block", return_value=0):
            summary, rows = run_bundle()
        self.assertGreater(summary["failed"], 0)
        self.assertTrue(any(row["case_id"] == "B001" and row["status"] == "FAIL" for row in rows))
