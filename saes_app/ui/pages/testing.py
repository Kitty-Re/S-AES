from PySide6.QtWidgets import QCheckBox, QFileDialog

from ...services.checks import run_checks
from ...services.exchange import export_vectors, verify_csv
from ..tasks import TaskPanel
from ..widgets import Card, Page, Table, actions, button, label


class TestingPage(Page):
    def __init__(self):
        super().__init__("LEVEL 02 / VERIFICATION", "自检与交叉测试", "核对教材参数和固定向量，或通过 CSV 交换相同明文、密钥下的加解密结果。")
        card = Card("算法自检")
        self.exhaustive = QCheckBox("附加：固定密钥 4AF5，遍历全部 65,536 个分组")
        self.task = TaskPanel("运行算法自检")
        self.task.start_button.clicked.connect(self.start_checks)
        self.task.succeeded.connect(self.show_checks)
        self.task.idle.connect(lambda: self.exhaustive.setEnabled(True))
        self.checks = Table(("检查项", "实际", "期望", "结论"), 195)
        card.body.addWidget(self.exhaustive)
        card.body.addWidget(self.task)
        card.body.addWidget(self.checks)
        self.body.addWidget(card)
        exchange = Card("CSV 交换与验证")
        exchange.body.addWidget(label("组间交叉测试暂不开展。导出样例仅供本地演练；导入真实他组数据后，才能记录组间测试结论。"))
        self.export_button = button("导出本地样例 CSV", self.export)
        self.import_button = button("导入并双向验证", self.import_file, True)
        exchange.body.addLayout(actions(self.export_button, self.import_button))
        self.summary = label("尚未导入数据")
        self.exchange_table = Table(("CSV 行", "明文", "密钥", "文件密文", "实际密文", "结论"), 200)
        exchange.body.addWidget(self.summary)
        exchange.body.addWidget(self.exchange_table)
        self.body.addWidget(exchange)
        self.finish_layout()

    def start_checks(self):
        if self.task.running:
            return
        exhaustive = self.exhaustive.isChecked()
        self.exhaustive.setEnabled(False)
        self.checks.setRowCount(0)
        self.task.start(lambda **kwargs: run_checks(exhaustive, **kwargs))

    def show_checks(self, result):
        self.checks.set_rows((name, actual, expected, "通过" if passed else "未通过") for name, actual, expected, passed in result.rows)

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出本地测试向量", "local-vectors.csv", "CSV (*.csv)")
        if path:
            self.guard(lambda: export_vectors(path))

    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入测试向量", "", "CSV (*.csv)")
        if path:
            self.import_path(path)

    def import_path(self, path):
        self.summary.setText("尚未导入数据")
        self.exchange_table.setRowCount(0)

        def operation():
            rows = verify_csv(path)
            count = sum(row.passed for row in rows)
            self.summary.setText(f"文件验证通过 {count}/{len(rows)} 行 · 结果仅针对当前导入文件")
            self.exchange_table.set_rows((row.line, row.plaintext, row.key, row.ciphertext, row.actual_ciphertext,
                                          "通过" if row.passed else row.error) for row in rows[:200])
        self.guard(operation)
