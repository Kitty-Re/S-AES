"""通过实际 Qt 控件操作并保存窗口截图。"""

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from saes_app.ui.main_window import MainWindow
from saes_app.ui.theme import apply_theme


def wait_task(app, task):
    deadline = time.perf_counter() + 15
    while task.running and time.perf_counter() < deadline:
        app.processEvents()
        QTest.qWait(5)
    if task.running:
        task.cancel()
        raise RuntimeError("截图等待后台任务超时。")
    app.processEvents()


def main():
    output = ROOT / "docs" / "evidence" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication([])
    apply_theme(app)
    window = MainWindow()
    window.resize(1240, 1000)
    window.show()
    app.processEvents()
    binary, text, multiple, attack, cbc, testing = window.pages
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
    window.close()
    app.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
