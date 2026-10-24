"""完整 2^16 + 2^16 密钥枚举的中间相遇攻击，保留碰撞桶中的全部 K1。"""

from dataclasses import dataclass
from threading import Event
from time import perf_counter
from typing import Callable

from ..core import generate_subkeys, validate_int
from ..core.cipher import _decrypt, _encrypt


@dataclass(frozen=True)
class AttackResult:
    candidates: tuple[tuple[int, int], ...]
    checked: int
    total: int
    first_pair_matches: int
    distinct_intermediates: int
    elapsed: float
    completed: bool
    pairs: tuple[tuple[int, int], ...]


def meet_in_the_middle(pairs, progress: Callable[[int, int], None] | None = None,
                       cancel: Event | None = None) -> AttackResult:
    pairs = tuple(pairs)
    if not pairs:
        raise ValueError("至少需要一组明文与双重加密密文。")
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("每一组数据需要明文和密文两个值。")
        validate_int(pair[0], 16, "已知明文")
        validate_int(pair[1], 16, "已知密文")
    pairs = tuple((plain, cipher) for plain, cipher in pairs)
    started, total, checked = perf_counter(), 131072, 0
    forward: dict[int, list[int]] = {}
    candidates, matches = [], 0
    plain, cipher = pairs[0]

    def stopped():
        return cancel is not None and cancel.is_set()

    def report():
        if progress:
            progress(checked, total)

    report()
    for first in range(65536):
        if stopped():
            break
        middle = _encrypt(plain, generate_subkeys(first))
        forward.setdefault(middle, []).append(first)
        checked += 1
        if checked % 512 == 0:
            report()
    if checked == 65536 and not stopped():
        for second in range(65536):
            if stopped():
                break
            second_keys = generate_subkeys(second)
            middle = _decrypt(cipher, second_keys)
            for first in forward.get(middle, ()):
                matches += 1
                first_keys = generate_subkeys(first)
                if all(_encrypt(_encrypt(p, first_keys), second_keys) == c for p, c in pairs[1:]):
                    candidates.append((first, second))
            checked += 1
            if checked % 512 == 0:
                report()
    report()
    return AttackResult(tuple(sorted(candidates)), checked, total, matches, len(forward),
                        perf_counter() - started, checked == total, pairs)
