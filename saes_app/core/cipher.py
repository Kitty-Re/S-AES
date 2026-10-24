"""教材附录 D 的 16 位 S-AES；状态按列排列为 [n0 n2; n1 n3]。"""

from dataclasses import dataclass
from functools import lru_cache

SBOX = (0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7)
INV_SBOX = (0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE)


def validate_int(value: int, width: int, name: str = "输入") -> int:
    if type(value) is not int or not 0 <= value < (1 << width):
        raise ValueError(f"{name}必须是 0～{(1 << width) - 1} 的整数（{width} 位）。")
    return value


def gf_multiply(left: int, right: int) -> int:
    """GF(2^4) 乘法，模多项式 x^4 + x + 1（0b10011）。"""
    validate_int(left, 4, "左操作数")
    validate_int(right, 4, "右操作数")
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x10:
            left ^= 0x13
        right >>= 1
    return product


def substitute(state: int, inverse: bool = False) -> int:
    validate_int(state, 16, "状态")
    box = INV_SBOX if inverse else SBOX
    return sum(box[(state >> shift) & 15] << shift for shift in (12, 8, 4, 0))


def shift_rows(state: int) -> int:
    validate_int(state, 16, "状态")
    return (state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)


def mix_columns(state: int, inverse: bool = False) -> int:
    validate_int(state, 16, "状态")
    diagonal, off_diagonal = (9, 2) if inverse else (1, 4)
    result = 0
    for shift in (8, 0):
        top, bottom = (state >> (shift + 4)) & 15, (state >> shift) & 15
        result |= (gf_multiply(diagonal, top) ^ gf_multiply(off_diagonal, bottom)) << (shift + 4)
        result |= (gf_multiply(off_diagonal, top) ^ gf_multiply(diagonal, bottom)) << shift
    return result


def expand_words(key: int) -> tuple[int, ...]:
    validate_int(key, 16, "密钥")
    words = [key >> 8, key & 255]
    for constant in (0x80, 0x30):
        previous = words[-1]
        # RotNib 后 SubNib，RCON 作用于高半字节。
        transformed = (SBOX[previous & 15] << 4) | SBOX[previous >> 4]
        words.extend((words[-2] ^ constant ^ transformed, 0))
        words[-1] = words[-2] ^ previous
    return tuple(words)


def _subkeys(key: int) -> tuple[int, int, int]:
    words = expand_words(key)
    return tuple((words[index] << 8) | words[index + 1] for index in (0, 2, 4))


# 缓存放在输入校验之后，避免 True 与整数 1 的缓存键混用。
_cached_subkeys = lru_cache(maxsize=65536)(_subkeys)


def generate_subkeys(key: int) -> tuple[int, int, int]:
    validate_int(key, 16, "密钥")
    return _cached_subkeys(key)


def _sub_shift(state: int, box: tuple[int, ...]) -> int:
    return (box[state >> 12] << 12) | (box[state & 15] << 8) | (box[(state >> 4) & 15] << 4) | box[(state >> 8) & 15]


# 查表只合并与密钥无关的变换；trace_block 保留逐步实现供核对。
_SUB_SHIFT = tuple(_sub_shift(value, SBOX) for value in range(65536))
_INV_SUB_SHIFT = tuple(_sub_shift(value, INV_SBOX) for value in range(65536))
_MIX = tuple(mix_columns(value) for value in range(256))
_INV_MIX = tuple(mix_columns(value, True) for value in range(256))


def _encrypt(block: int, keys: tuple[int, int, int]) -> int:
    state = _SUB_SHIFT[block ^ keys[0]]
    state = (_MIX[state >> 8] << 8) | _MIX[state & 255]
    return _SUB_SHIFT[state ^ keys[1]] ^ keys[2]


def _decrypt(block: int, keys: tuple[int, int, int]) -> int:
    state = _INV_SUB_SHIFT[block ^ keys[2]] ^ keys[1]
    state = (_INV_MIX[state >> 8] << 8) | _INV_MIX[state & 255]
    return _INV_SUB_SHIFT[state] ^ keys[0]


def encrypt_block(block: int, key: int) -> int:
    validate_int(block, 16, "明文分组")
    return _encrypt(block, generate_subkeys(key))


def decrypt_block(block: int, key: int) -> int:
    validate_int(block, 16, "密文分组")
    return _decrypt(block, generate_subkeys(key))


@dataclass(frozen=True)
class TraceStep:
    name: str
    value: int
    detail: str


@dataclass(frozen=True)
class BlockTrace:
    output: int
    round_keys: tuple[int, int, int]
    steps: tuple[TraceStep, ...]


def trace_block(block: int, key: int, decrypt: bool = False) -> BlockTrace:
    validate_int(block, 16, "分组")
    keys = generate_subkeys(key)
    steps = [TraceStep("输入分组", block, "按列填入 2×2 半字节矩阵")]
    if decrypt:
        operations = (("密钥加 K2", lambda s: s ^ keys[2]),
                      ("逆行移位", shift_rows), ("逆半字节代替", lambda s: substitute(s, True)),
                      ("密钥加 K1", lambda s: s ^ keys[1]),
                      ("逆列混淆", lambda s: mix_columns(s, True)),
                      ("逆行移位", shift_rows), ("逆半字节代替", lambda s: substitute(s, True)),
                      ("密钥加 K0", lambda s: s ^ keys[0]))
    else:
        operations = (("密钥加 K0", lambda s: s ^ keys[0]),
                      ("半字节代替 1", substitute), ("行移位 1", shift_rows),
                      ("列混淆", mix_columns), ("密钥加 K1", lambda s: s ^ keys[1]),
                      ("半字节代替 2", substitute), ("行移位 2", shift_rows),
                      ("密钥加 K2", lambda s: s ^ keys[2]))
    state = block
    for name, operation in operations:
        state = operation(state)
        detail = f"[{state >> 12:X} {(state >> 4) & 15:X}; {(state >> 8) & 15:X} {state & 15:X}]"
        steps.append(TraceStep(name, state, detail))
    return BlockTrace(state, keys, tuple(steps))
