"""读取他组数据，调用本组公开接口，回填 220 行结果；不运行数据包中的代码。"""

import argparse
import csv
import hashlib
import io
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SOURCE = ROOT / "docs/evidence/cross-test/peer-original"
OUTPUT = SOURCE.parent
ARCHIVE_NAME = "S-AES-cross-test-20261024.zip"
ARCHIVED_DOCUMENTS = {"00_互测说明.md", "09_results_template.csv", "10_local_verification.json"}

from saes_app import __version__
from saes_app.core import decrypt_block, encrypt_block, generate_subkeys
from saes_app.services.attack import meet_in_the_middle
from saes_app.services.cbc import compare_tampering, decrypt_cbc, encrypt_cbc
from saes_app.services.exchange import verify_csv, write_csv
from saes_app.services.formats import from_blocks, pad, parse_bits, parse_bytes, to_blocks, unpad
from saes_app.services.multiple import decrypt_multiple, encrypt_multiple, multiple_trace
from saes_app.services.text_cipher import ascii_bytes, decrypt_bytes, encrypt_bytes
from tests.reference import encrypt as reference_encrypt


def read_source_bytes(source, name):
    """原始说明、空白模板和发送方自检记录从完整 ZIP 读取。"""
    if Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("原始数据名称必须是普通文件名。")
    source = Path(source)
    archive = source.parent / ARCHIVE_NAME
    if name in ARCHIVED_DOCUMENTS and archive.is_file():
        with zipfile.ZipFile(archive) as package:
            return package.read(f"{archive.stem}/{name}")
    return (source / name).read_bytes()


def verify_manifest(source):
    """只接受当前目录中的普通文件名，逐字节核验原包清单。"""
    hashes = {}
    for line in (source / "manifest.sha256").read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        expected, name = line.split("  ", 1)
        if Path(name).name != name or "/" in name or "\\" in name or name in hashes:
            raise ValueError("原包清单存在重复名称或非普通文件名。")
        actual = hashlib.sha256(read_source_bytes(source, name)).hexdigest()
        if actual != expected:
            raise ValueError(f"原始文件 SHA-256 不一致：{name}")
        hashes[name] = actual
    return hashes


def padding_enabled(name):
    if name not in ("none", "PKCS7_2bytes"):
        raise ValueError("未知的他组填充约定。")
    return name != "none"


def crypt_message(data, case, decrypt=False):
    """复合已有单分组接口，填充仅在最外层添加或移除一次。"""
    modes = {"single": (1, None), "double_EE32": (2, "double"), "triple_EEE48": (3, "triple3")}
    count, mode = modes[case["algorithm"]]
    if len(case["keys_hex"]) != count:
        raise ValueError("密钥段数与消息模式不符。")
    combined = int("".join(case["keys_hex"]), 16)
    if combined != int(case["combined_key_hex"], 16):
        raise ValueError("组合密钥与各段密钥不一致。")
    padding = padding_enabled(case["padding"])
    if not decrypt and padding:
        data = pad(data)
    if mode is None:
        output = (decrypt_bytes if decrypt else encrypt_bytes)(data, combined)
    else:
        operation = decrypt_multiple if decrypt else encrypt_multiple
        output = from_blocks(operation(block, combined, mode) for block in to_blocks(data))
    return unpad(output) if decrypt and padding else output


def _json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def run_bundle(source=SOURCE, output=None):
    source = Path(source)
    started = perf_counter()
    tested_on = datetime.now(timezone(timedelta(hours=8))).date().isoformat()
    hashes = verify_manifest(source)
    with io.StringIO(read_source_bytes(source, "09_results_template.csv").decode("utf-8-sig"), newline="") as stream:
        reader = csv.DictReader(stream)
        headers = reader.fieldnames
        rows = [dict(row, actual_hex_or_text="", status="NOT_RUN", note="") for row in reader]
    indexed = {(row["case_id"], row["direction"]): row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError("回填模板存在重复用例方向。")
    details, basic, candidates = {}, [], {}
    cases = {}

    def put(case_id, direction, actual, valid=True, note=""):
        row = indexed[(case_id, direction)]
        row["actual_hex_or_text"] = actual
        row["status"] = "PASS" if valid and actual == row["expected_hex_or_text"] else "FAIL"
        row["note"] = f"S-AES {__version__}; {tested_on}" + ("; " + note if note else "")

    with (source / "01_basic.csv").open(encoding="utf-8-sig", newline="") as stream:
        basics = list(csv.DictReader(stream))
    gui_vectors = _json(source / "01_basic_gui.json")
    adapted = []
    for case, gui in zip(basics, gui_vectors, strict=True):
        plain, key, cipher = (int(case[name + "_hex"], 16) for name in ("plaintext", "key", "ciphertext"))
        formats_ok = all(parse_bits(case[name + "_binary"]) == int(case[name + "_hex"], 16)
                         and gui[name] == case[name + "_binary"] for name in ("plaintext", "key", "ciphertext"))
        subkeys = [f"{value:04X}" for value in generate_subkeys(key)]
        keys_ok = subkeys == [case[f"K{i}_hex"] for i in range(3)]
        actual, recovered = encrypt_block(plain, key), decrypt_block(cipher, key)
        reference = reference_encrypt(plain, key)
        valid = formats_ok and keys_ok and reference == cipher
        put(case["id"], "encrypt", f"{actual:04X}", valid, "round_keys=" + "/".join(subkeys))
        put(case["id"], "decrypt", f"{recovered:04X}", valid)
        basic.append({"case_id": case["id"], "plaintext": case["plaintext_binary"], "key": case["key_binary"],
                      "peer_ciphertext": case["ciphertext_binary"], "actual_ciphertext": f"{actual:016b}",
                      "recovered_plaintext": f"{recovered:016b}", "reference_ciphertext": f"{reference:016b}",
                      "round_keys_match": keys_ok, "passed": valid and actual == cipher and recovered == plain})
        adapted.append((case["plaintext_binary"], case["key_binary"], case["ciphertext_binary"]))
    cases["basic"] = len(basics)

    ascii_cases = _json(source / "02_ascii.json")
    for case in ascii_cases:
        plain, cipher = bytes.fromhex(case["plaintext_hex"]), bytes.fromhex(case["ciphertext_hex"])
        actual, recovered = crypt_message(plain, case), crypt_message(cipher, case, True)
        padded = pad(plain) if padding_enabled(case["padding"]) else plain
        valid = ascii_bytes(case["plaintext_text"]) == plain and padded.hex().upper() == case["padded_plaintext_hex"]
        put(case["id"], "encrypt", actual.hex().upper(), valid)
        put(case["id"], "decrypt", recovered.hex().upper(), valid)
    cases["ascii"] = len(ascii_cases)

    for filename, feature, mode in (("03_double.json", "double", "double"), ("04_triple48.json", "triple48", "triple3")):
        vectors = _json(source / filename)
        for case in vectors:
            plain, key, cipher = (int(case[name + "_hex"], 16) for name in ("plaintext", "combined_key", "ciphertext"))
            states = [f"{value:04X}" for value in multiple_trace(plain, key, mode)[1:]]
            reference = plain
            for subkey in case["keys_hex"]:
                reference = reference_encrypt(reference, int(subkey, 16))
            valid = states == case["stage_ciphertext_hex"] and reference == cipher
            put(case["id"], "encrypt", f"{encrypt_multiple(plain, key, mode):04X}", valid)
            put(case["id"], "decrypt", f"{decrypt_multiple(cipher, key, mode):04X}", valid)
            details[case["id"]] = {"stages": states, "stages_match": valid}
        cases[feature] = len(vectors)

    vectors = _json(source / "05_mitm.json")
    for case in vectors:
        pairs = [(int(pair["plaintext_hex"], 16), int(pair["ciphertext_hex"], 16)) for pair in case["pairs"]]
        result = meet_in_the_middle(pairs)
        keys = [f"{first:04X}{second:04X}" for first, second in result.candidates]
        canonical = "".join(key + "\n" for key in keys).encode("ascii")
        digest = hashlib.sha256(canonical).hexdigest()
        known = case["known_valid_key_hex"]
        unique = case["expected_unique_key_hex"]
        valid = (result.completed and digest == case["candidate_set_sha256"] and known in keys
                 and (unique is None or keys == [unique]))
        put(case["id"], "search", f"count={len(keys)}; known_key={known if known in keys else 'MISSING'}", valid,
            f"checked={result.checked}; candidate_sha256={digest}")
        details[case["id"]] = {"candidate_count": len(keys), "candidate_set_sha256": digest,
                               "expected_sha256": case["candidate_set_sha256"], "hash_matches": digest == case["candidate_set_sha256"],
                               "completed": result.completed, "checked": result.checked, "elapsed_seconds": result.elapsed}
        candidates[case["id"]] = canonical
    cases["mitm"] = len(vectors)

    cbc_cases = _json(source / "06_cbc.json")
    for case in cbc_cases:
        key, iv = int(case["combined_key_hex"], 16), int(case["iv_hex"], 16)
        plain, cipher = bytes.fromhex(case["plaintext_hex"]), bytes.fromhex(case["ciphertext_hex"])
        padding = padding_enabled(case["padding"])
        actual, recovered = encrypt_cbc(plain, key, iv, padding), decrypt_cbc(cipher, key, iv, padding)
        padded = pad(plain) if padding else plain
        previous, reference = iv, []
        for block in to_blocks(padded):
            previous = reference_encrypt(block ^ previous, key)
            reference.append(previous)
        valid = padded.hex().upper() == case["padded_plaintext_hex"] and from_blocks(reference) == cipher
        put(case["id"], "encrypt", actual.hex().upper(), valid)
        put(case["id"], "decrypt", recovered.hex().upper(), valid)
    cases["cbc"] = len(cbc_cases)

    vectors = _json(source / "07_cbc_tamper.json")
    for case in vectors:
        key, original_iv, modified_iv = (int(case[field], 16) for field in ("key_hex", "original_iv_hex", "modified_iv_hex"))
        original, modified = bytes.fromhex(case["original_ciphertext_hex"]), bytes.fromhex(case["modified_ciphertext_hex"])
        before, after = decrypt_cbc(original, key, original_iv, False), decrypt_cbc(modified, key, modified_iv, False)
        blocks = [{"block_1based": i + 1, "original_plaintext_hex": f"{a:04X}", "modified_plaintext_hex": f"{b:04X}",
                   "xor_difference_hex": f"{a ^ b:04X}"} for i, (a, b) in enumerate(zip(to_blocks(before), to_blocks(after), strict=True))]
        affected = [block["block_1based"] for block in blocks if block["xor_difference_hex"] != "0000"]
        valid = before.hex().upper() == case["original_raw_plaintext_hex"] and blocks == case["blocks"] and affected == case["expected_affected_blocks"]
        if case["operation"] == "flip_iv_bit":
            valid = valid and original == modified and original_iv ^ (1 << case["bit_index_lsb0"]) == modified_iv
        else:
            index = case["ciphertext_block_1based"] - 1
            replacement = int(case["replacement_hex"], 16) if case["operation"] == "replace_ciphertext_block" else None
            mask = 1 << case["bit_index_lsb0"] if replacement is None else 0
            comparison = compare_tampering(to_blocks(original), key, original_iv, index, mask, replacement)
            valid = valid and original_iv == modified_iv and from_blocks(row.modified_ciphertext for row in comparison) == modified
        status, decrypted = "not_used", after.hex().upper()
        if padding_enabled(case["padding"]):
            try:
                decrypted = unpad(after).hex().upper()
                status = "valid"
            except ValueError:
                status, decrypted = "invalid", None
        valid = valid and status == case["expected_pkcs7_status"] and decrypted == case["expected_decrypted_hex"]
        put(case["id"], "raw_decrypt", after.hex().upper(), valid, f"pkcs7={status}; affected_blocks={affected}")
        details[case["id"]] = {"pkcs7_status": status, "affected_blocks": affected, "blocks": blocks}
    cases["tamper"] = len(vectors)

    vectors = _json(source / "08_invalid_inputs.json")
    for case in vectors:
        api, data = case["api"], case["input"]
        try:
            if api == "parse_word":
                if data["base"] == "binary":
                    parse_bits(data["text"])
                else:
                    parsed = parse_bytes(data["text"])
                    if len(parsed) != 2:
                        raise ValueError("需要两个字节。")
            elif api == "encrypt_block":
                encrypt_block(int(data["plaintext_hex"], 16), data["key_integer"])
            elif api == "ascii_bytes":
                ascii_bytes(data["text"])
            elif api == "crypt_bytes":
                encrypt_bytes(bytes.fromhex(data["plaintext_hex"]), int(data["keys_hex"][0], 16))
            elif api == "cbc_encrypt":
                encrypt_cbc(bytes.fromhex(data["plaintext_hex"]), int(data["key_hex"], 16), data["iv_integer"], padding_enabled(data.get("padding", "none")))
            elif api == "cbc_decrypt":
                decrypt_cbc(bytes.fromhex(data["ciphertext_hex"]), int(data["key_hex"], 16), int(data["iv_hex"], 16), padding_enabled(data["padding"]))
            elif api == "meet_in_middle":
                meet_in_the_middle(data["pairs"])
            else:
                raise RuntimeError("没有对应的本组输入验证接口。")
        except ValueError:
            actual = "REJECT"
        except Exception as issue:
            actual = "ERROR:" + type(issue).__name__
        else:
            actual = "ACCEPT"
        put(case["id"], "validation", actual)
    cases["invalid"] = len(vectors)

    counts = Counter(row["status"] for row in rows)
    by_feature = {feature: {"rows": sum(row["feature"] == feature for row in rows),
                            "passed": sum(row["feature"] == feature and row["status"] == "PASS" for row in rows)} for feature in cases}
    archive = source.parent / ARCHIVE_NAME
    summary = {"source": "peer_group_dataset", "program_version": __version__,
               "tested_on": tested_on,
               "source_archive": archive.name, "source_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest() if archive.exists() else None,
               "manifest_verified_files": len(hashes), "source_file_sha256": hashes, "case_counts": cases,
               "case_total": sum(cases.values()), "result_rows": len(rows), "passed": counts["PASS"], "failed": counts["FAIL"],
               "not_run": counts["NOT_RUN"], "by_feature": by_feature, "basic_vectors": len(basic),
               "basic_passed": sum(row["passed"] for row in basic), "mitm": {k: v for k, v in details.items() if k.startswith("M")},
               "elapsed_seconds": perf_counter() - started, "verification_scope": "our_implementation_against_peer_vectors"}
    if output is not None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        write_csv(output / "peer-vectors-import.csv", ("plaintext", "key", "ciphertext"), adapted)
        checks = verify_csv(output / "peer-vectors-import.csv")
        if [row.passed for row in checks] != [row["passed"] for row in basic]:
            raise ValueError("CSV 导入验证与数据包检查结论不一致。")
        write_csv(output / "cross-test-results.csv", headers, ([row[name] for name in headers] for row in rows))
        write_csv(output / "basic-cross-results.csv", tuple(basic[0]), (tuple(row.values()) for row in basic))
        for name, value in (("cross-test-summary.json", summary), ("cross-test-details.json", details)):
            (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for case_id, content in candidates.items():
            (output / f"{case_id}-candidates.txt").write_bytes(content)
    return summary, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    arguments = parser.parse_args()
    summary, rows = run_bundle(arguments.source, arguments.output)
    print(json.dumps({name: summary[name] for name in ("case_total", "result_rows", "passed", "failed", "not_run", "by_feature", "mitm")}, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] == summary["result_rows"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
