import sys


def main():
    from PySide6.QtWidgets import QApplication
    from .ui.main_window import MainWindow
    from .ui.theme import apply_theme

    app = QApplication(sys.argv)
    apply_theme(app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
