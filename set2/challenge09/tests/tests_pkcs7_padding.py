import unittest

from set2.challenge09.pkcs7_padding import *


class TestPKCS7Padding(unittest.TestCase):

    def test_pkcs7_pad_none_bytes_raises_typeerror(self):
        with self.assertRaises(TypeError):
            pkcs7_pad(None, 1)

    def test_pkcs7_pad_empty_bytes_adds_padding(self):
        b = b''
        expected_padded = b"\x04\x04\x04\x04"

        actual_padded = pkcs7_pad(b, 4)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_zero_blk_size_returns_bytes_unchanged(self):
        b = b'YELLOW SUBMARINE'
        expected_padded = b"YELLOW SUBMARINE"

        actual_padded = pkcs7_pad(b, 0)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_negative_blk_size_returns_bytes_unchanged(self):
        b = b'YELLOW SUBMARINE'
        expected_padded = b"YELLOW SUBMARINE"

        actual_padded = pkcs7_pad(b, -1)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_blk_size_over_bounds_returns_bytes_unchanged(self):
        b = b'YELLOW SUBMARINE'
        expected_padded = b"YELLOW SUBMARINE"

        actual_padded = pkcs7_pad(b, 256)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_cryptopals_case(self):
        b = b"YELLOW SUBMARINE"
        expected_padded = b"YELLOW SUBMARINE\x04\x04\x04\x04"

        actual_padded = pkcs7_pad(b, 20)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_bytes_size_mutliple_of_blk_size_adds_extra_block(self):
        b = b"YELLOW"
        expected_padded = b"YELLOW\x03\x03\x03"

        actual_padded = pkcs7_pad(b, 3)

        self.assertEqual(expected_padded, actual_padded)
