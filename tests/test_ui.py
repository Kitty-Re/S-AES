import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from saes_app.services.exchange import export_vectors
from saes_app.services.formats import parse_bytes
from saes_app.ui.main_window import MainWindow
from saes_app.ui.tasks import TaskPanel
from saes_app.ui.theme import apply_theme


class UiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        apply_theme(cls.app)

    def setUp(self):
        self.errors = []
        self.old_hook = sys.excepthook
        sys.excepthook = lambda kind, error, trace: self.errors.append(str(error))
        self.window = MainWindow()
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        for task in self.window.findChildren(TaskPanel):
            task.cancel()
            self.wait_task(task)
        self.window.close()
        self.app.processEvents()
        sys.excepthook = self.old_hook
        self.assertEqual(self.errors, [], "Qt 槽函数不得产生未处理异常")

    def wait_task(self, task, timeout=10):
        deadline = time.perf_counter() + timeout
        while task.running and time.perf_counter() < deadline:
            self.app.processEvents()
            QTest.qWait(2)
        self.app.processEvents()
        self.assertFalse(task.running, "后台任务超时")

    def test_binary_buttons_trace_and_copy(self):
        page = self.window.pages[0]
        QTest.mouseClick(page.example_button, Qt.MouseButton.LeftButton)
        self.assertEqual(page.output.copy_value, "0010010011101100")
        self.assertEqual(page.trace.rowCount(), 9)
        QTest.mouseClick(page.output.copy_button, Qt.MouseButton.LeftButton)
        self.assertEqual(QApplication.clipboard().text(), page.output.copy_value)
        page.block.setText(page.output.copy_value)
        QTest.mouseClick(page.decrypt_button, Qt.MouseButton.LeftButton)
        self.assertEqual(page.output.copy_value, "1101011100101000")

    def test_keyboard_navigation_enter_and_invalid_input(self):
        page = self.window.pages[0]
        page.block.setText("1101011100101000")
        page.key.setText("0100101011110101")
        QTest.keyClick(page.block, Qt.Key.Key_Return)
        self.assertEqual(page.output.copy_value, "0010010011101100")
        page.key.setText("1")
        self.assertEqual(page.output.copy_value, "")
        QTest.mouseClick(page.encrypt_button, Qt.MouseButton.LeftButton)
        self.assertTrue(page.error.isVisible())
        self.window.navigation.setFocus()
        QTest.keyClick(self.window.navigation, Qt.Key.Key_Down)
        self.assertEqual(self.window.stack.currentIndex(), 1)

    def test_ascii_round_trip_and_format_conversion(self):
        self.window.navigation.setCurrentRow(1)
        page = self.window.pages[1]
        QTest.mouseClick(page.example_button, Qt.MouseButton.LeftButton)
        self.assertEqual(page.recovered.toPlainText(), "This is a test")
        cipher = parse_bytes(page.cipher.toPlainText())
        page.format.setCurrentText("Base64")
        self.assertEqual(parse_bytes(page.cipher.toPlainText(), "Base64"), cipher)
        QTest.mouseClick(page.decrypt_button, Qt.MouseButton.LeftButton)
        self.assertEqual(page.recovered.toPlainText(), "This is a test")
        page.format.setCurrentText("二进制")
        self.assertEqual(parse_bytes(page.cipher.toPlainText(), "二进制"), cipher)

    def test_ascii_errors_and_invalid_format_recovery(self):
        self.window.navigation.setCurrentRow(1)
        page = self.window.pages[1]
        page.plain.setPlainText("中文")
        QTest.mouseClick(page.encrypt_button, Qt.MouseButton.LeftButton)
        self.assertTrue(page.error.isVisible())
        page.cipher.setPlainText("GG")
        page.format.setCurrentText("Base64")
        self.assertEqual(page.format.currentText(), "十六进制")
        self.assertEqual(page.cipher.toPlainText(), "GG")
        page.plain.setPlainText("A")
        page.padding.setChecked(False)
        page.encrypt()
        self.assertIn("偶数", page.error.text())

    def test_all_multiple_modes_via_controls(self):
        self.window.navigation.setCurrentRow(2)
        page = self.window.pages[2]
        for index in range(3):
            page.mode.setCurrentIndex(index)
            QTest.mouseClick(page.example_button, Qt.MouseButton.LeftButton)
            cipher = page.output.copy_value
            self.assertEqual(len(cipher), 16)
            page.block.setText(cipher)
            QTest.mouseClick(page.decrypt_button, Qt.MouseButton.LeftButton)
            self.assertEqual(page.output.copy_value, "1101011100101000")

    def test_attack_background_result_and_export(self):
        self.window.navigation.setCurrentRow(3)
        page = self.window.pages[3]
        QTest.mouseClick(page.task.start_button, Qt.MouseButton.LeftButton)
        self.assertFalse(page.pairs.isEnabled())
        self.wait_task(page.task)
        self.assertEqual(page.result.candidates, ((0x4AF5, 0x3A94),))
        self.assertTrue(page.pairs.isEnabled())
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "candidates.csv")
            with patch("saes_app.ui.pages.attack.QFileDialog.getSaveFileName", return_value=(path, "")):
                QTest.mouseClick(page.export_button, Qt.MouseButton.LeftButton)
            self.assertIn("True,131072", Path(path).read_text(encoding="utf-8-sig"))

    def test_attack_cancel_and_invalid_pairs(self):
        page = self.window.pages[3]
        page.start()
        page.task.cancel()
        self.wait_task(page.task)
        self.assertFalse(page.result.completed)
        self.assertIn("未完成", page.summary.text())
        page.pairs.setRowCount(0)
        page.start()
        self.assertIn("至少", page.error.text())

    def test_cbc_controls_tamper_and_packet_exchange(self):
        self.window.navigation.setCurrentRow(4)
        page = self.window.pages[4]
        QTest.mouseClick(page.example_button, Qt.MouseButton.LeftButton)
        self.assertEqual(page.recovered.toPlainText(), "Hello, S-AES CBC!")
        self.assertEqual(page.table.item(1, 5).text(), "0001")
        self.assertEqual(page.table.item(2, 5).text(), "0000")
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "packet.json")
            cipher = page.cipher.toPlainText()
            with patch("saes_app.ui.pages.cbc.QFileDialog.getSaveFileName", return_value=(path, "")):
                QTest.mouseClick(page.export_button, Qt.MouseButton.LeftButton)
            page.iv.setText("0" * 16)
            page.cipher.clear()
            with patch("saes_app.ui.pages.cbc.QFileDialog.getOpenFileName", return_value=(path, "")):
                QTest.mouseClick(page.import_button, Qt.MouseButton.LeftButton)
            self.assertEqual(page.cipher.toPlainText(), cipher)
            self.assertEqual(page.iv.text(), f"{0x1234:016b}")
            page.decrypt()
            self.assertEqual(page.recovered.toPlainText(), "Hello, S-AES CBC!")

    def test_cbc_invalid_input_and_replacement(self):
        page = self.window.pages[4]
        page.example()
        page.tamper_mode.setCurrentIndex(1)
        page.mask.setText("0" * 16)
        page.tamper()
        self.assertEqual(page.table.item(0, 2).text(), "0000")
        page.index.setValue(65000)
        page.tamper()
        self.assertIn("超出", page.error.text())
        page.cipher.setPlainText("GG")
        page.decrypt()
        self.assertTrue(page.error.text())

    def test_checks_and_csv_local_import(self):
        self.window.navigation.setCurrentRow(5)
        page = self.window.pages[5]
        page.exhaustive.setChecked(True)
        QTest.mouseClick(page.task.start_button, Qt.MouseButton.LeftButton)
        self.wait_task(page.task)
        self.assertEqual(page.checks.rowCount(), 8)
        self.assertEqual(page.checks.item(7, 3).text(), "通过")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local.csv"
            export_vectors(path)
            page.import_path(path)
            self.assertIn("8/8", page.summary.text())
            self.assertEqual(page.exchange_table.rowCount(), 8)

    def test_background_error_recovery_and_restart(self):
        page = self.window.pages[5]

        def failing(**kwargs):
            raise ValueError("测试异常")
        page.task.start(failing)
        self.wait_task(page.task)
        self.assertIn("测试异常", page.task.status.text())
        page.start_checks()
        self.wait_task(page.task)
        self.assertEqual(page.checks.rowCount(), 7)

    def test_close_window_cancels_worker_cleanly(self):
        page = self.window.pages[3]
        page.start()
        self.window.close()
        self.wait_task(page.task)
        QTest.qWait(50)
        self.app.processEvents()
        self.assertFalse(self.window.isVisible())

    def test_compact_layout_all_pages(self):
        self.window.resize(960, 640)
        for index, page in enumerate(self.window.pages):
            self.window.navigation.setCurrentRow(index)
            self.app.processEvents()
            scroll = self.window.stack.widget(index)
            self.assertLessEqual(page.minimumSizeHint().width(), scroll.viewport().width())
