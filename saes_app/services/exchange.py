"""组间 CSV 格式，导出本地向量不代表已经完成组间交叉测试。"""

import csv
from dataclasses import dataclass
from pathlib import Path

from ..core import decrypt_block, encrypt_block
from .formats import parse_bits

SAMPLE_PAIRS = ((0xD728, 0x4AF5), (0xA749, 0x2D55), (0, 0), (0xFFFF, 0xFFFF),
                (1, 1), (0x1234, 0x5678), (0xAAAA, 0x5555), (0x8000, 0x0001))


@dataclass(frozen=True)
class CrossCheck:
    line: int
    plaintext: str
    key: str
    ciphertext: str
    actual_ciphertext: str
    recovered_plaintext: str
    passed: bool
    error: str


def export_vectors(path, pairs=SAMPLE_PAIRS) -> None:
    rows = [(f"{plain:016b}", f"{key:016b}", f"{encrypt_block(plain, key):016b}") for plain, key in pairs]
    write_csv(path, ("plaintext", "key", "ciphertext"), rows)


def write_csv(path, headers, rows) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(headers)
        writer.writerows(rows)


def verify_csv(path) -> tuple[CrossCheck, ...]:
    results = []
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or len(reader.fieldnames) != 3 or set(reader.fieldnames) != {"plaintext", "key", "ciphertext"}:
            raise ValueError("CSV 表头必须包含且仅包含 plaintext,key,ciphertext，允许调整列顺序。")
        for line, row in enumerate(reader, 2):
            plain_text, key_text, cipher_text = (row.get(name) or "" for name in ("plaintext", "key", "ciphertext"))
            actual, recovered, error = "", "", ""
            try:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("列数与表头不符。")
                plain = parse_bits(plain_text, 16, "明文")
                key = parse_bits(key_text, 16, "密钥")
                cipher = parse_bits(cipher_text, 16, "密文")
                actual = f"{encrypt_block(plain, key):016b}"
                recovered = f"{decrypt_block(cipher, key):016b}"
                if int(actual, 2) != cipher or int(recovered, 2) != plain:
                    error = "加密或解密结果与文件不一致。"
            except ValueError as issue:
                error = str(issue)
            results.append(CrossCheck(line, plain_text, key_text, cipher_text, actual, recovered, not error, error))
    if not results:
        raise ValueError("CSV 没有测试数据。")
    return tuple(results)
