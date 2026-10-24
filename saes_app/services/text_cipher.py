"""ASCII 两字节分组；原始字节接口与文本填充接口分开。"""

from ..core import decrypt_block, encrypt_block, generate_subkeys
from .formats import from_blocks, pad, to_blocks, unpad


def ascii_bytes(text: str) -> bytes:
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"第 {error.start + 1} 个字符不是 ASCII 字符。") from error


def encrypt_bytes(data: bytes, key: int) -> bytes:
    generate_subkeys(key)
    return from_blocks(encrypt_block(block, key) for block in to_blocks(data))


def decrypt_bytes(data: bytes, key: int) -> bytes:
    generate_subkeys(key)
    return from_blocks(decrypt_block(block, key) for block in to_blocks(data))


def encrypt_text(text: str, key: int, padding: bool = True) -> bytes:
    data = ascii_bytes(text)
    return encrypt_bytes(pad(data) if padding else data, key)


def decrypt_text(data: bytes, key: int, padding: bool = True) -> str:
    plain = decrypt_bytes(data, key)
    plain = unpad(plain) if padding else plain
    try:
        return plain.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("解密字节中存在非 ASCII 值，请核对密钥；原始字节未被丢弃。") from error


def escaped_bytes(data: bytes) -> str:
    """用转义表示显示不可打印密文字节，Latin-1 保证 0～255 一一对应。"""
    return data.decode("latin-1").encode("unicode_escape").decode("ascii")
