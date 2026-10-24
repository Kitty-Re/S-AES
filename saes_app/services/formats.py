"""严格解析位串和字节格式，保留前导零。"""

import base64
import binascii
import re


def parse_bits(text: str, width: int = 16, name: str = "输入") -> int:
    text = text.strip()
    if len(text) != width or any(char not in "01" for char in text):
        raise ValueError(f"{name}需要恰好 {width} 位二进制，只能包含 0 和 1。")
    return int(text, 2)


def format_bytes(data: bytes, kind: str = "十六进制") -> str:
    if kind == "十六进制":
        return data.hex(" ").upper()
    if kind == "二进制":
        return " ".join(f"{byte:08b}" for byte in data)
    if kind == "Base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError("未知密文格式。")


def parse_bytes(text: str, kind: str = "十六进制") -> bytes:
    compact = "".join(text.split())
    if kind == "十六进制":
        if len(compact) % 2 or re.fullmatch(r"[0-9a-fA-F]*", compact) is None:
            raise ValueError("十六进制密文需要成对的 0～9、A～F 字符。")
        return bytes.fromhex(compact)
    if kind == "二进制":
        if len(compact) % 8 or any(char not in "01" for char in compact):
            raise ValueError("二进制密文只能包含 0、1，长度须为 8 的倍数。")
        return bytes(int(compact[index:index + 8], 2) for index in range(0, len(compact), 8))
    if kind == "Base64":
        try:
            result = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Base64 格式或填充不合法。") from error
        if base64.b64encode(result).decode("ascii") != compact:
            raise ValueError("需要规范 Base64 编码（含正确的等号填充）。")
        return result
    raise ValueError("未知密文格式。")


def require_bytes(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise ValueError("数据必须是 bytes。")


def to_blocks(data: bytes) -> tuple[int, ...]:
    require_bytes(data)
    if len(data) % 2:
        raise ValueError("原始分组数据必须为偶数字节；文本可选择 PKCS#7 填充。")
    return tuple(int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2))


def from_blocks(blocks) -> bytes:
    from ..core import validate_int
    output = bytearray()
    for block in blocks:
        validate_int(block, 16, "分组")
        output.extend(block.to_bytes(2, "big"))
    return bytes(output)


def pad(data: bytes) -> bytes:
    require_bytes(data)
    count = 2 - len(data) % 2
    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    require_bytes(data)
    if not data or len(data) % 2 or data[-1] not in (1, 2) or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("PKCS#7 填充不合法，请核对密钥、IV、密文和填充选项。")
    return data[:-data[-1]]
