import json
import tempfile
import unittest
from pathlib import Path
from threading import Event

from saes_app.core import decrypt_block, encrypt_block
from saes_app.services.attack import meet_in_the_middle
from saes_app.services.cbc import (
    compare_tampering, decrypt_blocks, decrypt_cbc, encrypt_blocks, encrypt_cbc,
    export_packet, import_packet, random_iv,
)
from saes_app.services.checks import run_checks
from saes_app.services.exchange import export_vectors, verify_csv
from saes_app.services.formats import format_bytes, from_blocks, pad, parse_bits, parse_bytes, to_blocks, unpad
from saes_app.services.multiple import decrypt_multiple, encrypt_multiple, split_keys
from saes_app.services.text_cipher import decrypt_bytes, decrypt_text, encrypt_bytes, encrypt_text, escaped_bytes


class FormatAndTextTests(unittest.TestCase):
    def test_bits_keep_width_and_reject_invalid(self):
        self.assertEqual(parse_bits(" 0000000000000001 "), 1)
        for text in ("1", "0" * 17, "0" * 15 + "x", "00000000 00000000"):
            with self.assertRaises(ValueError):
                parse_bits(text)

    def test_all_byte_values_in_all_formats(self):
        raw = bytes(range(256))
        for kind in ("十六进制", "二进制", "Base64"):
            self.assertEqual(parse_bytes(format_bytes(raw, kind), kind), raw)
            self.assertEqual(parse_bytes("", kind), b"")
        self.assertEqual(parse_bytes("01\n02 00 FF"), b"\x01\x02\x00\xff")

    def test_invalid_encodings(self):
        for text, kind in (("0", "十六进制"), ("GG", "十六进制"), ("01", "二进制"), ("2" * 8, "二进制"),
                           ("Zh==", "Base64"), ("abc", "Base64"), ("====", "Base64"), ("é", "Base64")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_bytes(text, kind)

    def test_pkcs7_empty_odd_even_and_trailing_zero(self):
        for data in (b"", b"A", b"AB", b"ABC", b"AB\x00", b"A\x01", b"\x02\x02"):
            padded = pad(data)
            self.assertEqual(len(padded) % 2, 0)
            self.assertGreater(len(padded), len(data))
            self.assertEqual(unpad(padded), data)
        for invalid in (b"", b"A", b"AB", b"\x01\x02", b"\x00\x00"):
            with self.assertRaises(ValueError):
                unpad(invalid)

    def test_ascii_round_trips_and_raw_bytes(self):
        for text in ("", "A", "AB", "This is a test", "A\x00\n\t\x7f", "".join(map(chr, range(128)))):
            self.assertEqual(decrypt_text(encrypt_text(text, 0x4AF5), 0x4AF5), text)
        raw = bytes(range(256))
        self.assertEqual(decrypt_bytes(encrypt_bytes(raw, 0x4AF5), 0x4AF5), raw)
        self.assertEqual(decrypt_text(encrypt_text("AB", 0, False), 0, False), "AB")

    def test_ascii_and_odd_byte_errors(self):
        for text in ("中文", "🙂"):
            with self.assertRaises(ValueError):
                encrypt_text(text, 0)
        with self.assertRaises(ValueError):
            encrypt_text("A", 0, False)
        with self.assertRaises(ValueError):
            decrypt_bytes(b"\x00", 0)
        with self.assertRaises(ValueError):
            encrypt_bytes("AB", 0)
        with self.assertRaises(ValueError):
            decrypt_text(encrypt_bytes(b"\xff\xff", 0), 0, False)

    def test_big_endian_blocks_and_escaped_cipher(self):
        self.assertEqual(to_blocks(b"\x01\x02\xab\xcd"), (0x0102, 0xABCD))
        self.assertEqual(from_blocks((0x0102, 0xABCD)), b"\x01\x02\xab\xcd")
        self.assertEqual(escaped_bytes(b"A\x00\xff"), "A\\x00\\xff")


class MultipleTests(unittest.TestCase):
    def test_explicit_composition_and_inverse(self):
        key1, key2, key3, plain = 0x4AF5, 0x3A94, 0x1234, 0xD728
        twice = encrypt_block(encrypt_block(plain, key1), key2)
        expected = {"double": twice, "triple2": encrypt_block(twice, key1), "triple3": encrypt_block(twice, key3)}
        for mode in expected:
            key = (key1 << 16) | key2 if mode != "triple3" else (key1 << 32) | (key2 << 16) | key3
            self.assertEqual(encrypt_multiple(plain, key, mode), expected[mode])
            self.assertEqual(decrypt_multiple(expected[mode], key, mode), plain)
        self.assertEqual(split_keys(0x4AF53A94, "triple2"), (key1, key2, key1))

    def test_boundary_values_and_mode_errors(self):
        for mode, width in (("double", 32), ("triple2", 32), ("triple3", 48)):
            for plain in (0, 1, 65535):
                key = (1 << width) - 1
                self.assertEqual(decrypt_multiple(encrypt_multiple(plain, key, mode), key, mode), plain)
            with self.assertRaises(ValueError):
                encrypt_multiple(0, 1 << width, mode)
        with self.assertRaises(ValueError):
            split_keys(0, "unknown")


class AttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = tuple((plain, encrypt_multiple(plain, 0x4AF53A94)) for plain in (0xD728, 0x1234, 0xABCD))
        cls.single = meet_in_the_middle(cls.pairs[:1])
        cls.multiple = meet_in_the_middle(cls.pairs)

    def test_complete_single_pair_retains_collisions(self):
        result = self.single
        self.assertTrue(result.completed)
        self.assertEqual(result.checked, 131072)
        self.assertIn((0x4AF5, 0x3A94), result.candidates)
        self.assertLess(result.distinct_intermediates, 65536)
        self.assertEqual(len(result.candidates), result.first_pair_matches)
        plain, cipher = self.pairs[0]
        middle = decrypt_block(cipher, 0x3A94)
        expected = {key for key in range(65536) if encrypt_block(plain, key) == middle}
        actual = {a for a, b in result.candidates if b == 0x3A94}
        self.assertEqual(actual, expected)

    def test_multiple_pairs_find_unique_example(self):
        self.assertEqual(self.multiple.candidates, ((0x4AF5, 0x3A94),))
        self.assertTrue(self.multiple.completed)
        self.assertTrue(set(self.multiple.candidates).issubset(self.single.candidates))

    def test_contradictory_pairs(self):
        result = meet_in_the_middle(((0, 0), (0, 1)))
        self.assertTrue(result.completed)
        self.assertEqual(result.candidates, ())

    def test_cancel_before_and_during_table_build(self):
        stop = Event()
        stop.set()
        result = meet_in_the_middle(self.pairs, cancel=stop)
        self.assertEqual(result.checked, 0)
        self.assertFalse(result.completed)
        stop.clear()

        def progress(checked, total):
            if checked >= 512:
                stop.set()
        result = meet_in_the_middle(self.pairs, progress=progress, cancel=stop)
        self.assertEqual(result.checked, 512)
        self.assertFalse(result.completed)
        self.assertEqual(result.candidates, ())

    def test_cancel_during_reverse_search(self):
        stop = Event()

        def progress(checked, total):
            if checked >= 66048:
                stop.set()
        result = meet_in_the_middle(self.pairs[:1], progress=progress, cancel=stop)
        self.assertEqual(result.checked, 66048)
        self.assertFalse(result.completed)
        for first, second in result.candidates:
            self.assertEqual(encrypt_multiple(self.pairs[0][0], (first << 16) | second), self.pairs[0][1])

    def test_attack_validation(self):
        for pairs in ([], [(0, 65536)], [(True, 0)], [(0,)], [0]):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                meet_in_the_middle(pairs)


class CbcTests(unittest.TestCase):
    def test_cbc_formula_and_inverse(self):
        plain, key, iv = (0x1234, 0x5678, 0xABCD), 0x4AF5, 0x1111
        cipher = encrypt_blocks(plain, key, iv)
        self.assertEqual(cipher[0], encrypt_block(plain[0] ^ iv, key))
        self.assertEqual(cipher[1], encrypt_block(plain[1] ^ cipher[0], key))
        self.assertEqual(decrypt_blocks(cipher, key, iv), plain)

    def test_bytes_padding_all_lengths_and_unicode(self):
        for length in range(65):
            plain = bytes(range(length))
            self.assertEqual(decrypt_cbc(encrypt_cbc(plain, 0x4AF5, 0x1234), 0x4AF5, 0x1234), plain)
        data = "简化 AES 工作模式".encode("utf-8")
        self.assertEqual(decrypt_cbc(encrypt_cbc(data, 3, 4), 3, 4), data)
        self.assertEqual(encrypt_cbc(b"", 0, 0, False), b"")

    def test_xor_tampering_precise_propagation(self):
        plain = (0x1111, 0x2222, 0x3333, 0x4444, 0x5555)
        cipher = encrypt_blocks(plain, 0x4AF5, 0x1234)
        rows = compare_tampering(cipher, 0x4AF5, 0x1234, 1, 0x0040)
        self.assertEqual(rows[0].xor_difference, 0)
        self.assertNotEqual(rows[1].xor_difference, 0)
        self.assertEqual(rows[2].xor_difference, 0x0040)
        self.assertEqual(rows[2].changed_bits, 1)
        self.assertEqual(rows[3].xor_difference, 0)
        self.assertEqual(rows[4].xor_difference, 0)

    def test_replacement_last_block_and_iv_changes(self):
        plain, key, iv = (1, 2, 3, 4), 0x4AF5, 0x1234
        cipher = encrypt_blocks(plain, key, iv)
        rows = compare_tampering(cipher, key, iv, 0, replacement=0)
        self.assertEqual(rows[1].xor_difference, cipher[0])
        rows = compare_tampering(cipher, key, iv, 3, 1)
        self.assertTrue(all(row.xor_difference == 0 for row in rows[:3]))
        changed = decrypt_blocks(cipher, key, iv ^ 0x10)
        self.assertEqual(changed[0], plain[0] ^ 0x10)
        self.assertEqual(changed[1:], plain[1:])

    def test_packet_shares_iv_without_key(self):
        cipher = encrypt_cbc(b"Hello", 0x4AF5, 0x1234)
        text = export_packet(cipher, 0x1234)
        self.assertNotIn("key", json.loads(text))
        self.assertEqual(import_packet(text), (cipher, 0x1234, True))
        self.assertEqual(import_packet(export_packet(b"", 0, False)), (b"", 0, False))
        for _ in range(32):
            self.assertTrue(0 <= random_iv() < 65536)

    def test_invalid_packets_and_inputs(self):
        for text in ("{", "[]", "{}", '{"algorithm":"AES","version":1}'):
            with self.assertRaises(ValueError):
                import_packet(text)
        good = json.loads(export_packet(b"\x00\x00", 0))
        for field, value in (("version", True), ("iv", "0x00"), ("padding", "unknown"), ("ciphertext_base64", "AA==")):
            bad = dict(good, **{field: value})
            with self.assertRaises(ValueError):
                import_packet(json.dumps(bad))
        for operation in (lambda: encrypt_blocks([True], 0, 0), lambda: decrypt_blocks([], 0, -1),
                          lambda: decrypt_cbc(b"", 0, 0), lambda: encrypt_cbc(b"A", 0, 0, False),
                          lambda: compare_tampering([0], 0, 0, 1), lambda: compare_tampering([0], 0, 0, 0, -1)):
            with self.assertRaises(ValueError):
                operation()


class ExchangeAndCheckTests(unittest.TestCase):
    def test_csv_local_round_trip_and_reordered_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.csv"
            export_vectors(path)
            self.assertEqual(len(verify_csv(path)), 8)
            self.assertTrue(all(row.passed for row in verify_csv(path)))
            path.write_text("key,plaintext,ciphertext\n0100101011110101,1101011100101000,0010010011101100\n", encoding="utf-8")
            self.assertTrue(verify_csv(path)[0].passed)

    def test_csv_row_errors_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text("plaintext,key,ciphertext\n0,0,0\n0000000000000000,0000000000000000,0000000000000000\n0,0,0,extra\n", encoding="utf-8")
            rows = verify_csv(path)
            self.assertEqual(len(rows), 3)
            self.assertFalse(any(row.passed for row in rows))
            self.assertTrue(all(row.error for row in rows))
            for content in ("a,b,c\n", "plaintext,key,ciphertext\n", "key,key,ciphertext\n"):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_csv(path)

    def test_quick_and_exhaustive_checks_and_cancel(self):
        self.assertTrue(all(row[3] for row in run_checks().rows))
        result = run_checks(True)
        self.assertTrue(result.completed)
        self.assertEqual(result.checked, 65536)
        stop = Event()
        stop.set()
        self.assertFalse(run_checks(True, cancel=stop).completed)
