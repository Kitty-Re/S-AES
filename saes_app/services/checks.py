"""界面可运行的教材参数检查；完整独立参考验证见 tests。"""

from dataclasses import dataclass
from time import perf_counter

from ..core import decrypt_block, encrypt_block, generate_subkeys, mix_columns, shift_rows, substitute


@dataclass(frozen=True)
class CheckResult:
    rows: tuple[tuple[str, str, str, bool], ...]
    checked: int
    elapsed: float
    completed: bool


def run_checks(exhaustive=False, progress=None, cancel=None) -> CheckResult:
    started = perf_counter()
    specs = (("附录 D.2.2 半字节代替", substitute(0x8A1C), 0x604C),
             ("附录 D.2.3 行移位", shift_rows(0x604C), 0x6C40),
             ("附录 D.2.4 列混淆", mix_columns(0x6C40), 0x3743),
             ("附录 D.3 K1", generate_subkeys(0x2D55)[1], 0xBCE9),
             ("附录 D.3 K2", generate_subkeys(0x2D55)[2], 0xA34A),
             ("固定向量 D728 / 4AF5", encrypt_block(0xD728, 0x4AF5), 0x24EC),
             ("固定向量逆运算", decrypt_block(0x24EC, 0x4AF5), 0xD728))
    rows = [(name, f"{actual:04X}", f"{expected:04X}", actual == expected) for name, actual, expected in specs]
    checked, total = 0, 65536 if exhaustive else 0
    completed = True
    if exhaustive:
        for block in range(total):
            if cancel is not None and cancel.is_set():
                completed = False
                break
            if decrypt_block(encrypt_block(block, 0x4AF5), 0x4AF5) != block:
                raise ValueError(f"分组 {block:04X} 的往返检查失败。")
            checked += 1
            if progress and checked % 512 == 0:
                progress(checked, total)
        rows.append(("固定密钥全部分组往返", str(checked), str(total), completed))
    if progress:
        progress(checked if exhaustive else len(rows), total if exhaustive else len(rows))
    return CheckResult(tuple(rows), checked, perf_counter() - started, completed)
