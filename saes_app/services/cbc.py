"""S-AES CBC 与原始分组篡改实验。JSON 数据包携带 IV、填充约定，不保存密钥。"""

import base64
import json
import secrets
from dataclasses import dataclass

from ..core import decrypt_block, encrypt_block, generate_subkeys, validate_int
from .formats import from_blocks, pad, parse_bytes, to_blocks, unpad


def random_iv() -> int:
    return secrets.randbits(16)


def _validated(blocks, key, iv):
    generate_subkeys(key)
    validate_int(iv, 16, "IV")
    blocks = tuple(blocks)
    for block in blocks:
        validate_int(block, 16, "分组")
    return blocks


def encrypt_blocks(blocks, key: int, iv: int) -> tuple[int, ...]:
    blocks = _validated(blocks, key, iv)
    output, previous = [], iv
    for block in blocks:
        previous = encrypt_block(block ^ previous, key)
        output.append(previous)
    return tuple(output)


def decrypt_blocks(blocks, key: int, iv: int) -> tuple[int, ...]:
    blocks = _validated(blocks, key, iv)
    output, previous = [], iv
    for block in blocks:
        output.append(decrypt_block(block, key) ^ previous)
        previous = block
    return tuple(output)


def encrypt_cbc(data: bytes, key: int, iv: int, padding: bool = True) -> bytes:
    return from_blocks(encrypt_blocks(to_blocks(pad(data) if padding else data), key, iv))


def decrypt_cbc(data: bytes, key: int, iv: int, padding: bool = True) -> bytes:
    blocks = to_blocks(data)
    if padding and not blocks:
        raise ValueError("带填充的 CBC 密文至少包含一个分组。")
    plain = from_blocks(decrypt_blocks(blocks, key, iv))
    return unpad(plain) if padding else plain


def export_packet(ciphertext: bytes, iv: int, padding: bool = True) -> str:
    validate_int(iv, 16, "IV")
    to_blocks(ciphertext)
    if padding and not ciphertext:
        raise ValueError("带填充的 CBC 密文不能为空。")
    return json.dumps({"algorithm": "S-AES-CBC", "version": 1, "iv": f"{iv:04X}",
                       "padding": "PKCS7-2" if padding else "none",
                       "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii")},
                      ensure_ascii=False, indent=2)


def import_packet(text: str) -> tuple[bytes, int, bool]:
    try:
        packet = json.loads(text)
        if not isinstance(packet, dict) or packet.get("algorithm") != "S-AES-CBC" or type(packet.get("version")) is not int or packet["version"] != 1:
            raise ValueError("数据包算法或版本不匹配。")
        iv_text, kind, encoded = packet["iv"], packet["padding"], packet["ciphertext_base64"]
        if not isinstance(iv_text, str) or len(iv_text) != 4 or any(c not in "0123456789abcdefABCDEF" for c in iv_text):
            raise ValueError("IV 必须是四位十六进制。")
        if kind not in ("PKCS7-2", "none") or not isinstance(encoded, str):
            raise ValueError("数据包填充或密文格式不合法。")
        data = parse_bytes(encoded, "Base64")
        to_blocks(data)
        if kind == "PKCS7-2" and not data:
            raise ValueError("带填充的 CBC 密文不能为空。")
        return data, int(iv_text, 16), kind == "PKCS7-2"
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("CBC JSON 数据包格式不合法或缺少字段。") from error


@dataclass(frozen=True)
class TamperRow:
    index: int
    ciphertext: int
    modified_ciphertext: int
    plaintext: int
    modified_plaintext: int
    xor_difference: int
    changed_bits: int


def compare_tampering(blocks, key: int, iv: int, index: int = 0,
                      xor_mask: int = 1, replacement: int | None = None) -> tuple[TamperRow, ...]:
    blocks = _validated(blocks, key, iv)
    if type(index) is not int or not 0 <= index < len(blocks):
        raise ValueError("篡改分组序号超出范围（从 0 开始）。")
    validate_int(xor_mask, 16, "异或掩码")
    if replacement is not None:
        validate_int(replacement, 16, "替换分组")
    modified = list(blocks)
    modified[index] = replacement if replacement is not None else modified[index] ^ xor_mask
    before, after = decrypt_blocks(blocks, key, iv), decrypt_blocks(modified, key, iv)
    return tuple(TamperRow(i, blocks[i], modified[i], before[i], after[i], before[i] ^ after[i],
                           (before[i] ^ after[i]).bit_count()) for i in range(len(blocks)))
