"""重跑完整测试和关卡实验，保存真实计算结果，不修改文档中的历史记录。"""

import csv
import hashlib
import io
import json
import os
import platform
import sys
import time
import unittest
from dataclasses import asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from saes_app import __version__
from saes_app.core import decrypt_block, encrypt_block, trace_block
from saes_app.services.attack import meet_in_the_middle
from saes_app.services.cbc import compare_tampering, decrypt_cbc, encrypt_cbc, export_packet
from saes_app.services.exchange import SAMPLE_PAIRS, export_vectors, verify_csv, write_csv
from saes_app.services.formats import to_blocks
from saes_app.services.multiple import decrypt_multiple, encrypt_multiple
from saes_app.services.text_cipher import decrypt_text, encrypt_text
from tests.reference import encrypt as reference_encrypt
from tools.verify_cross_test import run_bundle


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    output = ROOT / "docs" / "evidence" / "results"
    output.mkdir(parents=True, exist_ok=True)
    log = io.StringIO()
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    test_result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    test_elapsed = time.perf_counter() - started
    # 测试失败的 traceback 也不写入本机绝对路径。
    sanitized_log = log.getvalue().replace(str(ROOT), "[project]").replace(str(Path.home()), "[user]")
    (output / "unittest.txt").write_text(sanitized_log, encoding="utf-8")
    if not test_result.wasSuccessful():
        print(log.getvalue())
        return 1

    export_vectors(output / "local-vectors.csv")
    local = verify_csv(output / "local-vectors.csv")
    assert all(row.passed for row in local)
    reference_rows = []
    for plain, key in SAMPLE_PAIRS:
        actual, reference = encrypt_block(plain, key), reference_encrypt(plain, key)
        assert actual == reference
        reference_rows.append((f"{plain:016b}", f"{key:016b}", f"{actual:016b}", f"{reference:016b}", True))
    write_csv(output / "independent-reference.csv", ("plaintext", "key", "production", "reference", "passed"), reference_rows)
    save_json(output / "binary-trace.json", asdict(trace_block(0xA749, 0x2D55)))

    ascii_plain = "This is a test"
    ascii_cipher = encrypt_text(ascii_plain, 0x4AF5)
    ascii_restored = decrypt_text(ascii_cipher, 0x4AF5)
    assert ascii_restored == ascii_plain
    ascii_result = {"plaintext": ascii_plain, "key_hex": "4AF5", "padding": "PKCS7-2",
                    "ciphertext_hex": ascii_cipher.hex(" ").upper(), "restored": ascii_restored}
    save_json(output / "ascii.json", ascii_result)

    multiple = []
    for mode, key, width in (("double", 0x4AF53A94, 32), ("triple2", 0x4AF53A94, 32), ("triple3", 0x4AF53A941234, 48)):
        cipher = encrypt_multiple(0xD728, key, mode)
        restored = decrypt_multiple(cipher, key, mode)
        assert restored == 0xD728
        multiple.append({"mode": mode, "key_bits": f"{key:0{width}b}", "key_hex": f"{key:0{width // 4}X}",
                         "plaintext_hex": "D728", "ciphertext_hex": f"{cipher:04X}", "restored_hex": f"{restored:04X}"})
    save_json(output / "multiple.json", multiple)

    pairs = tuple((p, encrypt_multiple(p, 0x4AF53A94)) for p in (0xD728, 0x1234, 0xABCD))
    write_csv(output / "mitm-known-pairs.csv", ("plaintext", "ciphertext"), ((f"{p:016b}", f"{c:016b}") for p, c in pairs))
    attacks = []
    for count in (1, 2, 3):
        result = meet_in_the_middle(pairs[:count])
        assert result.completed and (0x4AF5, 0x3A94) in result.candidates
        value = asdict(result)
        value.pop("candidates")
        value.update(pair_count=count, candidate_count=len(result.candidates),
                     example_key_present=True, candidate_csv=f"mitm-candidates-{count}.csv")
        attacks.append(value)
        write_csv(output / f"mitm-candidates-{count}.csv",
                  ("key1", "key2", "combined_key", "completed", "checked", "elapsed_seconds"),
                  ((f"{a:016b}", f"{b:016b}", f"{a:016b}{b:016b}", result.completed, result.checked, f"{result.elapsed:.9f}") for a, b in result.candidates))
    save_json(output / "mitm.json", attacks)

    key, iv = 0x4AF5, 0x1234
    cbc_plain = b"Hello, S-AES CBC!"
    cbc_cipher = encrypt_cbc(cbc_plain, key, iv)
    cbc_restored = decrypt_cbc(cbc_cipher, key, iv)
    assert cbc_restored == cbc_plain
    tampered = compare_tampering(to_blocks(cbc_cipher), key, iv, 0, 1)
    assert tampered[0].changed_bits and tampered[1].xor_difference == 1
    assert all(row.changed_bits == 0 for row in tampered[2:])
    write_csv(output / "cbc-tamper.csv",
              ("index", "ciphertext", "modified_ciphertext", "plaintext", "modified_plaintext", "xor_difference", "changed_bits"),
              ((row.index, f"{row.ciphertext:04X}", f"{row.modified_ciphertext:04X}", f"{row.plaintext:04X}",
                f"{row.modified_plaintext:04X}", f"{row.xor_difference:04X}", row.changed_bits) for row in tampered))
    (output / "cbc-packet.json").write_text(export_packet(cbc_cipher, iv), encoding="utf-8")
    save_json(output / "cbc.json", {"plaintext": cbc_plain.decode(), "key_hex": "4AF5", "iv_hex": "1234",
                                   "padding": "PKCS7-2", "ciphertext_hex": cbc_cipher.hex(" ").upper(),
                                   "restored": cbc_restored.decode(), "tamper_index": 0, "xor_mask": "0001",
                                   "rows": [asdict(row) for row in tampered]})

    cross_test, _ = run_bundle(output=ROOT / "docs/evidence/cross-test")
    assert cross_test["passed"] == cross_test["result_rows"] and cross_test["not_run"] == 0

    import PySide6
    from PySide6.QtCore import qVersion
    source_pdf = ROOT / "docs" / "reference" / "附录D 简化AES.pdf"
    summary = {"project_version": __version__, "generated_on": datetime.now(timezone(timedelta(hours=8))).date().isoformat(),
               "environment": {"os": platform.system(), "python": platform.python_version(),
                               "pyside6": PySide6.__version__, "qt": qVersion()},
               "tests": {"count": test_result.testsRun, "failures": len(test_result.failures), "errors": len(test_result.errors),
                         "skipped": len(test_result.skipped), "elapsed_seconds": test_elapsed},
               "coverage": {"all_blocks_one_key": 65536, "all_keys_one_block": 65536,
                            "independent_reference_pairs": 4096, "full_key_block_space_tested": False},
               "cross_group_testing": "passed_peer_dataset", "members": [],
               "cross_test": {name: cross_test[name] for name in ("case_total", "result_rows", "passed", "failed", "basic_vectors", "basic_passed")},
               "ascii": ascii_result, "multiple": multiple, "mitm": attacks,
               "cbc": {"iv_hex": "1234", "ciphertext_hex": cbc_cipher.hex(" ").upper(),
                       "tamper_plaintext_xor": [f"{row.xor_difference:04X}" for row in tampered]},
               "source_pdf_sha256": hashlib.sha256(source_pdf.read_bytes()).hexdigest() if source_pdf.exists() else None}
    save_json(output / "summary.json", summary)
    print(json.dumps({"tests": summary["tests"], "mitm_candidates": [row["candidate_count"] for row in attacks],
                      "ascii": ascii_result, "multiple": multiple, "cbc": summary["cbc"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
