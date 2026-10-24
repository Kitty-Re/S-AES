from pathlib import Path

from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QSpinBox

from ...services.cbc import (
    compare_tampering, decrypt_cbc, encrypt_cbc, export_packet, import_packet, random_iv,
)
from ...services.formats import format_bytes, parse_bits, parse_bytes, to_blocks
from ..widgets import Card, Page, Table, actions, bits_input, button, field, label, text_input


class CbcPage(Page):
    def __init__(self):
        super().__init__("LEVEL 05 / CIPHER BLOCK CHAINING", "CBC 与密文篡改", "将长消息连接成密码分组链。共享 16 位 IV，并比较修改某个密文分组前后的解密结果。")
        card = Card("消息与初始向量")
        self.key = bits_input(value=f"{0x4AF5:016b}", title="CBC 密钥")
        self.iv = bits_input(value=f"{random_iv():016b}", title="CBC 初始向量 IV")
        row = QHBoxLayout()
        row.addLayout(field("主密钥 · 16 bit", self.key), 1)
        row.addLayout(field("IV · 16 bit", self.iv), 1)
        row.addWidget(button("随机 IV", self.generate_iv))
        card.body.addLayout(row)
        self.encoding = QComboBox()
        self.encoding.addItems(("UTF-8", "ASCII"))
        self.padding = QCheckBox("PKCS#7 填充")
        self.padding.setChecked(True)
        row = QHBoxLayout()
        row.addLayout(field("文本编码", self.encoding), 1)
        row.addWidget(self.padding, 2)
        card.body.addLayout(row)
        self.plain, self.cipher = text_input(72), text_input(72)
        row = QHBoxLayout()
        row.addLayout(field("明文消息", self.plain), 1)
        row.addLayout(field("密文 · 十六进制", self.cipher), 1)
        card.body.addLayout(row)
        self.encrypt_button = button("CBC 加密", self.encrypt, True)
        self.decrypt_button = button("CBC 解密", self.decrypt)
        self.example_button = button("填入示例", self.example)
        self.export_button = button("导出 IV 数据包", self.export)
        self.import_button = button("导入数据包", self.import_file)
        card.body.addLayout(actions(self.encrypt_button, self.decrypt_button, self.example_button))
        card.body.addLayout(actions(self.export_button, self.import_button))
        card.body.addWidget(label("随机 IV 来自系统随机源。导出的 JSON 包含 IV、密文和填充约定；密钥需另行共享。"))
        self.recovered = text_input(50, True)
        self.recovered.setAccessibleName("CBC 解密结果")
        self.status = label("")
        card.body.addWidget(self.status)
        card.body.addWidget(self.recovered)
        self.body.addWidget(card)
        tamper = Card("篡改实验 · 原始分组对比")
        self.index = QSpinBox()
        self.index.setRange(0, 65535)
        self.tamper_mode = QComboBox()
        self.tamper_mode.addItems(("异或翻转", "整组替换"))
        self.mask = bits_input(value=f"{1:016b}", title="篡改操作值")
        row = QHBoxLayout()
        row.addLayout(field("分组序号（从 0 开始）", self.index), 1)
        row.addLayout(field("操作", self.tamper_mode), 1)
        row.addLayout(field("掩码 / 替换值 · 16 bit", self.mask), 2)
        tamper.body.addLayout(row)
        self.tamper_button = button("比较篡改前后", self.tamper, True)
        tamper.body.addLayout(actions(self.tamper_button))
        self.tamper_summary = label("表格保留填充字节，便于直接观察分组差异。")
        self.table = Table(("分组", "原密文", "改后密文", "原明文", "改后明文", "XOR 差", "变化位数"), 190)
        tamper.body.addWidget(self.tamper_summary)
        tamper.body.addWidget(self.table)
        self.body.addWidget(tamper)
        for item in (self.key, self.iv):
            item.textChanged.connect(self.clear)
        self.cipher.textChanged.connect(self.clear)
        self.plain.textChanged.connect(self.clear)
        self.padding.toggled.connect(self.clear)
        self.encoding.currentTextChanged.connect(self.clear)
        self.index.valueChanged.connect(self.clear_tamper)
        self.tamper_mode.currentIndexChanged.connect(self.clear_tamper)
        self.mask.textChanged.connect(self.clear_tamper)
        self.finish_layout()

    def clear_tamper(self):
        self.table.setRowCount(0)
        self.tamper_summary.setText("表格保留填充字节，便于直接观察分组差异。")

    def clear(self):
        self.recovered.clear()
        self.status.clear()
        self.clear_tamper()

    def generate_iv(self):
        self.iv.setText(f"{random_iv():016b}")

    def parameters(self):
        return parse_bits(self.key.text(), name="密钥"), parse_bits(self.iv.text(), name="IV")

    def example(self):
        self.key.setText(f"{0x4AF5:016b}")
        self.iv.setText(f"{0x1234:016b}")
        self.plain.setPlainText("Hello, S-AES CBC!")
        self.padding.setChecked(True)
        self.index.setValue(0)
        self.tamper_mode.setCurrentIndex(0)
        self.mask.setText(f"{1:016b}")
        self.encrypt()
        self.decrypt()
        self.tamper()

    def encrypt(self):
        self.clear()

        def operation():
            key, iv = self.parameters()
            data = self.plain.toPlainText().encode(self.encoding.currentText())
            cipher = encrypt_cbc(data, key, iv, self.padding.isChecked())
            self.cipher.setPlainText(format_bytes(cipher))
            self.status.setText(f"加密完成 · 明文 {len(data)} Bytes · 密文 {len(cipher)} Bytes · IV {iv:04X}")
        self.guard(operation)

    def decrypt(self):
        self.clear()

        def operation():
            key, iv = self.parameters()
            data = decrypt_cbc(parse_bytes(self.cipher.toPlainText()), key, iv, self.padding.isChecked())
            try:
                text = data.decode(self.encoding.currentText())
            except UnicodeDecodeError as issue:
                self.recovered.setPlainText("原始字节 HEX：" + data.hex(" ").upper())
                raise ValueError("解密字节无法按所选编码显示，上方保留原始字节。") from issue
            self.recovered.setPlainText(text)
            self.status.setText(f"解密完成 · 恢复 {len(data)} Bytes · IV {iv:04X}")
        self.guard(operation)

    def tamper(self):
        self.clear_tamper()

        def operation():
            key, iv = self.parameters()
            blocks = to_blocks(parse_bytes(self.cipher.toPlainText()))
            value = parse_bits(self.mask.text(), name="操作值")
            index = self.index.value()
            replacement = value if self.tamper_mode.currentIndex() == 1 else None
            rows = compare_tampering(blocks, key, iv, index, value, replacement)
            changed = [str(row.index) for row in rows if row.changed_bits]
            self.tamper_summary.setText(f"变化的明文分组：{', '.join(changed) or '无'}。若 C[i] 改变 Δ，则 P[i+1] 精确异或 Δ；更后面的分组保持原值。显示前 200 组。")
            self.table.set_rows((r.index, f"{r.ciphertext:04X}", f"{r.modified_ciphertext:04X}", f"{r.plaintext:04X}", f"{r.modified_plaintext:04X}", f"{r.xor_difference:04X}", r.changed_bits) for r in rows[:200])
        self.guard(operation)

    def export(self):
        def operation():
            packet = export_packet(parse_bytes(self.cipher.toPlainText()), parse_bits(self.iv.text(), name="IV"), self.padding.isChecked())
            path, _ = QFileDialog.getSaveFileName(self, "保存 CBC 数据包", "saes-cbc.json", "JSON (*.json)")
            if path:
                Path(path).write_text(packet, encoding="utf-8")
        self.guard(operation)

    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开 CBC 数据包", "", "JSON (*.json)")
        if not path:
            return

        def operation():
            data, iv, padding = import_packet(Path(path).read_text(encoding="utf-8-sig"))
            self.iv.setText(f"{iv:016b}")
            self.padding.setChecked(padding)
            self.cipher.setPlainText(format_bytes(data))
            self.status.setText("已载入密文、IV 和填充约定；输入共享密钥并选择原文本编码后解密。")
        self.guard(operation)
