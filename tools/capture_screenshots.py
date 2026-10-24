"""通过实际 Qt 控件操作并保存窗口截图。"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from saes_app.ui.main_window import MainWindow
from saes_app.ui.theme import apply_theme
from saes_app import __version__


def wait_task(app, task):
    deadline = time.perf_counter() + 15
    while task.running and time.perf_counter() < deadline:
        app.processEvents()
        QTest.qWait(5)
    if task.running:
        task.cancel()
        raise RuntimeError("截图等待后台任务超时。")
    app.processEvents()


def capture_peer(app, window, testing, output):
    """实际点击导入按钮，记录全部 64 行的双向结果与首尾截图。"""
    window.resize(1320, 1120)
    window.navigation.setCurrentRow(5)
    testing.exhaustive.setChecked(True)
    testing.task.start_button.click()
    wait_task(app, testing.task)
    testing.import_path(ROOT / "docs/evidence/results/local-vectors.csv")
    app.processEvents()
    window.grab().save(str(output / "06-checks-local.png"))
    window.resize(960, 640)
    app.processEvents()
    window.grab().save(str(output / "06-checks-local-compact.png"))
    window.resize(1320, 1120)
    source = ROOT / "docs/evidence/cross-test/peer-vectors-import.csv"
    with patch("saes_app.ui.pages.testing.QFileDialog.getOpenFileName", return_value=(str(source), "")):
        testing.import_button.click()
    app.processEvents()
    assert len(testing.last_checks) == 64 and all(row.passed for row in testing.last_checks)
    assert testing.exchange_table.rowCount() == 64
    for index, row in enumerate(testing.last_checks):
        assert testing.exchange_table.item(index, 4).text() == f"{int(row.actual_ciphertext, 2):04X}"
        assert testing.exchange_table.item(index, 5).text() == f"{int(row.recovered_plaintext, 2):04X}"
    images = []
    for row, name in ((0, "11-peer-cross-top.png"), (63, "12-peer-cross-bottom.png")):
        testing.exchange_table.scrollToItem(testing.exchange_table.item(row, 0))
        app.processEvents()
        if not window.grab().save(str(output / name)):
            raise RuntimeError("交叉验证截图保存失败。")
        images.append("docs/evidence/screenshots/" + name)
    evidence = {"program_version": __version__, "input_csv": "peer-vectors-import.csv", "rows": 64,
                "encrypt_passed": sum(row.actual_ciphertext == row.ciphertext for row in testing.last_checks),
                "decrypt_passed": sum(row.recovered_plaintext == row.plaintext for row in testing.last_checks),
                "all_passed": all(row.passed for row in testing.last_checks), "window_size": [1320, 1120],
                "screenshots": images, "interaction": "Qt import button with selected CSV path"}
    (ROOT / "docs/evidence/cross-test/ui-evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("peer GUI: 64/64 encryption and decryption; screenshots saved")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer-only", action="store_true", help="只更新交叉验证界面截图")
    arguments = parser.parse_args()
    output = ROOT / "docs" / "evidence" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication([])
    apply_theme(app)
    window = MainWindow()
    window.resize(1240, 1000)
    window.show()
    app.processEvents()
    binary, text, multiple, attack, cbc, testing = window.pages
    if arguments.peer_only:
        capture_peer(app, window, testing, output)
        window.close()
        app.processEvents()
        return 0
    for page in (binary, text, multiple, cbc):
        page.example_button.click()
    attack.task.start_button.click()
    wait_task(app, attack.task)
    testing.exhaustive.setChecked(True)
    testing.task.start_button.click()
    wait_task(app, testing.task)
    # 本地交换功能截图与他组数据严格分开。
    local = ROOT / "docs" / "evidence" / "results" / "local-vectors.csv"
    if local.exists():
        testing.import_path(local)
    names = ("01-binary", "02-ascii", "03-double", "04-mitm", "05-cbc", "06-checks-local")
    for index, name in enumerate(names):
        window.navigation.setCurrentRow(index)
        app.processEvents()
        QTest.qWait(30)
        path = output / f"{name}.png"
        if not window.grab().save(str(path)):
            raise RuntimeError(f"无法保存截图：{path}")
        print(path.relative_to(ROOT))
    window.navigation.setCurrentRow(2)
    for mode, name in ((1, "07-triple32"), (2, "08-triple48")):
        multiple.mode.setCurrentIndex(mode)
        multiple.example_button.click()
        app.processEvents()
        window.grab().save(str(output / f"{name}.png"))
    window.navigation.setCurrentRow(4)
    scroll = window.stack.widget(4)
    scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum())
    app.processEvents()
    window.grab().save(str(output / "09-cbc-tamper.png"))
    window.resize(960, 640)
    for index, name in enumerate(names):
        window.navigation.setCurrentRow(index)
        app.processEvents()
        window.grab().save(str(output / f"{name}-compact.png"))
    capture_peer(app, window, testing, output)
    window.close()
    app.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
