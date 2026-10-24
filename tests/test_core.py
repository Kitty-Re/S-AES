import random
import unittest

from saes_app.core import (
    INV_SBOX, SBOX, decrypt_block, encrypt_block, expand_words, generate_subkeys,
    gf_multiply, mix_columns, shift_rows, substitute, trace_block,
)
from tests import reference


class CoreTests(unittest.TestCase):
    def test_sbox_from_field_inverse_and_affine_map(self):
        self.assertEqual(SBOX, reference.BOX)
        self.assertEqual(tuple(INV_SBOX[value] for value in SBOX), tuple(range(16)))

    def test_all_field_products_against_polynomial_reference(self):
        for left in range(16):
            for right in range(16):
                self.assertEqual(gf_multiply(left, right), reference.multiply(left, right))
        self.assertEqual(gf_multiply(4, 12), 5)

    def test_appendix_transform_examples(self):
        self.assertEqual(0xA749 ^ 0x2D55, 0x8A1C)
        self.assertEqual(substitute(0x8A1C), 0x604C)
        self.assertEqual(shift_rows(0x604C), 0x6C40)
        self.assertEqual(mix_columns(0x6C40), 0x3743)

    def test_appendix_key_schedule(self):
        self.assertEqual(expand_words(0x2D55), (0x2D, 0x55, 0xBC, 0xE9, 0xA3, 0x4A))
        self.assertEqual(generate_subkeys(0x2D55), (0x2D55, 0xBCE9, 0xA34A))
        self.assertEqual(generate_subkeys(0x4AF5), (0x4AF5, 0xDD28, 0x87AF))

    def test_fixed_vectors(self):
        for plain, key, cipher in ((0xD728, 0x4AF5, 0x24EC), (0xA749, 0x2D55, 0xC349)):
            self.assertEqual(encrypt_block(plain, key), cipher)
            self.assertEqual(decrypt_block(cipher, key), plain)

    def test_every_column_inverse(self):
        for value in range(256):
            self.assertEqual(mix_columns(mix_columns(value), True), value)
            self.assertEqual(mix_columns(mix_columns(value << 8), True), value << 8)

    def test_transform_inverses_all_states(self):
        for state in range(65536):
            self.assertEqual(shift_rows(shift_rows(state)), state)
            self.assertEqual(substitute(substitute(state), True), state)

    def test_all_blocks_are_a_permutation_and_round_trip(self):
        ciphertexts = set()
        for plain in range(65536):
            cipher = encrypt_block(plain, 0x4AF5)
            ciphertexts.add(cipher)
            self.assertEqual(decrypt_block(cipher, 0x4AF5), plain)
        self.assertEqual(len(ciphertexts), 65536)

    def test_every_key_round_trip(self):
        for key in range(65536):
            self.assertEqual(decrypt_block(encrypt_block(0xD728, key), key), 0xD728)

    def test_independent_matrix_reference_4096_pairs(self):
        rng = random.Random(20261024)
        samples = [(0, 0), (65535, 65535), (1, 1), (0x8000, 1)]
        samples += [(rng.randrange(65536), rng.randrange(65536)) for _ in range(4092)]
        for plain, key in samples:
            self.assertEqual(encrypt_block(plain, key), reference.encrypt(plain, key))
            self.assertEqual(list(generate_subkeys(key)), reference.round_keys(key))

    def test_trace_matches_optimized_path(self):
        rng = random.Random(24)
        for _ in range(256):
            plain, key = rng.randrange(65536), rng.randrange(65536)
            cipher = encrypt_block(plain, key)
            self.assertEqual(trace_block(plain, key).output, cipher)
            self.assertEqual(trace_block(cipher, key, True).output, plain)
        self.assertEqual([step.value for step in trace_block(0xA749, 0x2D55).steps],
                         [0xA749, 0x8A1C, 0x604C, 0x6C40, 0x3743, 0x8BAA, 0x6300, 0x6003, 0xC349])

    def test_strict_validation_including_cached_bool(self):
        generate_subkeys(1)
        for invalid in (-1, 65536, True, 1.0, "1", None):
            with self.subTest(invalid=invalid):
                for function in (generate_subkeys, expand_words, substitute, shift_rows, mix_columns):
                    with self.assertRaises(ValueError):
                        function(invalid)
                with self.assertRaises(ValueError):
                    encrypt_block(invalid, 0)
                with self.assertRaises(ValueError):
                    decrypt_block(0, invalid)
        for invalid in (-1, 16, True):
            with self.assertRaises(ValueError):
                gf_multiply(invalid, 1)
