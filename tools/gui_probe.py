"""独立进程的高 DPI 布局检查；由 QT_SCALE_FACTOR 指定缩放。"""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication
from saes_app.ui.main_window import MainWindow
from saes_app.ui.theme import apply_theme


def main():
    app = QApplication([])
    apply_theme(app)
    window = MainWindow()
    window.resize(1180, 900)
    window.show()
    for index, page in enumerate(window.pages):
        window.navigation.setCurrentRow(index)
        app.processEvents()
        scroll = window.stack.widget(index)
        if page.minimumSizeHint().width() > scroll.viewport().width():
            raise RuntimeError(f"页面 {index} 水平布局超出视口。")
    window.navigation.setCurrentRow(0)
    window.pages[0].example()
    app.processEvents()
    suffix = os.environ.get("QT_SCALE_FACTOR", "1").replace(".", "_")
    path = ROOT / "docs" / "evidence" / "screenshots" / f"10-binary-scale-{suffix}.png"
    window.grab().save(str(path))
    print(f"scale={suffix}, ratio={window.devicePixelRatioF()}, pages=6, passed")
    window.close()
    app.processEvents()


if __name__ == "__main__":
    main()
