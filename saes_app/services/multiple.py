"""双重 EE、32 位三重 EEE(K1,K2,K1) 和 48 位三重 EEE(K1,K2,K3)。"""

from ..core import decrypt_block, encrypt_block, validate_int

MODE_WIDTHS = {"double": 32, "triple2": 32, "triple3": 48}


def split_keys(key: int, mode: str = "double") -> tuple[int, ...]:
    if mode not in MODE_WIDTHS:
        raise ValueError("未知多重加密模式。")
    width = MODE_WIDTHS[mode]
    validate_int(key, width, "组合密钥")
    keys = tuple((key >> shift) & 0xFFFF for shift in range(width - 16, -1, -16))
    return keys + keys[:1] if mode == "triple2" else keys


def multiple_trace(block: int, key: int, mode: str = "double", decrypt: bool = False) -> tuple[int, ...]:
    validate_int(block, 16, "分组")
    keys = split_keys(key, mode)
    operation = decrypt_block if decrypt else encrypt_block
    values = [block]
    for subkey in reversed(keys) if decrypt else keys:
        values.append(operation(values[-1], subkey))
    return tuple(values)


def encrypt_multiple(block: int, key: int, mode: str = "double") -> int:
    return multiple_trace(block, key, mode)[-1]


def decrypt_multiple(block: int, key: int, mode: str = "double") -> int:
    return multiple_trace(block, key, mode, True)[-1]
