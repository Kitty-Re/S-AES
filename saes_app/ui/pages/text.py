from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout

from ...services.formats import format_bytes, parse_bits, parse_bytes, unpad
from ...services.text_cipher import ascii_bytes, decrypt_bytes, encrypt_text, escaped_bytes
from ..widgets import Card, Page, Table, actions, bits_input, button, field, label, text_input


class TextPage(Page):
    def __init__(self):
        super().__init__("LEVEL 03 / ASCII", "ASCII 文本", "每 2 Bytes 为一组。密文支持十六进制、二进制和 Base64，也提供原始字节的转义视图。")
        card = Card("文本与密钥")
        self.key = bits_input(value=f"{0x4AF5:016b}", title="ASCII 密钥")
        self.padding = QCheckBox("PKCS#7 填充（兼容奇数字符串，解密时自动移除）")
        self.padding.setChecked(True)
        self.format = QComboBox()
        self.format.addItems(("十六进制", "二进制", "Base64"))
        self._kind = "十六进制"
        row = QHBoxLayout()
        row.addLayout(field("主密钥 · 16 bit", self.key), 2)
        row.addLayout(field("密文显示格式", self.format), 1)
        card.body.addLayout(row)
        card.body.addWidget(self.padding)
        self.plain = text_input(95)
        self.cipher = text_input(95)
        row = QHBoxLayout()
        row.addLayout(field("ASCII 明文", self.plain), 1)
        row.addLayout(field("密文字节", self.cipher), 1)
        card.body.addLayout(row)
        self.encrypt_button = button("加密文本", self.encrypt, True)
        self.decrypt_button = button("解密密文", self.decrypt)
        self.example_button = button("填入示例", self.example)
        card.body.addLayout(actions(self.encrypt_button, self.decrypt_button, self.example_button))
        self.body.addWidget(card)
        result = Card("恢复结果与字节视图")
        self.recovered = text_input(60, True)
        self.raw = label("等待运算")
        self.summary = label("")
        result.body.addWidget(self.summary)
        result.body.addWidget(self.recovered)
        result.body.addWidget(self.raw)
        self.table = Table(("分组", "明文字节 HEX", "密文字节 HEX"), 165)
        result.body.addWidget(self.table)
        self.body.addWidget(result)
        self.format.currentTextChanged.connect(self.change_format)
        self.key.textChanged.connect(self.clear)
        self.padding.toggled.connect(self.clear)
        self.plain.textChanged.connect(self.clear)
        self.cipher.textChanged.connect(self.clear)
        self.finish_layout()

    def clear(self):
        self.recovered.clear()
        self.summary.clear()
        self.raw.setText("等待运算")
        self.table.setRowCount(0)

    def example(self):
        self.plain.setPlainText("This is a test")
        self.key.setText(f"{0x4AF5:016b}")
        self.padding.setChecked(True)
        self.encrypt()
        self.decrypt()

    def show_bytes(self, cipher, plain):
        self.summary.setText(f"密文 {len(cipher)} Bytes · {len(cipher) // 2} 个分组")
        self.raw.setText("密文原始字节（Latin-1 转义）：" + escaped_bytes(cipher))
        self.table.set_rows((i // 2, plain[i:i + 2].hex(" ").upper(), cipher[i:i + 2].hex(" ").upper())
                            for i in range(0, min(len(cipher), 400), 2))
        if len(cipher) > 400:
            self.summary.setText(self.summary.text() + " · 明细显示前 200 组，密文框保留全部数据")

    def encrypt(self):
        self.clear()

        def operation():
            key = parse_bits(self.key.text(), name="密钥")
            cipher = encrypt_text(self.plain.toPlainText(), key, self.padding.isChecked())
            self.cipher.setPlainText(format_bytes(cipher, self._kind))
            self.show_bytes(cipher, decrypt_bytes(cipher, key))
        self.guard(operation)

    def decrypt(self):
        self.clear()

        def operation():
            cipher = parse_bytes(self.cipher.toPlainText(), self._kind)
            raw = decrypt_bytes(cipher, parse_bits(self.key.text(), name="密钥"))
            self.show_bytes(cipher, raw)
            plain = unpad(raw) if self.padding.isChecked() else raw
            try:
                decoded = plain.decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError("解密结果含非 ASCII 字节；上方保留完整字节视图，请核对密钥。") from error
            self.recovered.setPlainText(decoded)
        self.guard(operation)

    def change_format(self, kind):
        old = self._kind
        try:
            data = parse_bytes(self.cipher.toPlainText(), old)
        except ValueError as issue:
            self.format.blockSignals(True)
            self.format.setCurrentText(old)
            self.format.blockSignals(False)
            self.show_error(str(issue))
            return
        self._kind = kind
        self.cipher.setPlainText(format_bytes(data, kind))
