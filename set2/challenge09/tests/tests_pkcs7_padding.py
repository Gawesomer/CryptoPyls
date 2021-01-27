import unittest

from set2.challenge09.pkcs7_padding import pkcs7_pad, pkcs7_unpad, \
    InvalidPaddingException


class TestPKCS7Padding(unittest.TestCase):

    def test_pkcs7_pad_none_bytes_raises_typeerror(self):
        with self.assertRaises(TypeError):
            pkcs7_pad(None, 1)

    def test_pkcs7_pad_empty_bytes_adds_padding(self):
        b = b''
        expected_padded = b"\x04\x04\x04\x04"

        actual_padded = pkcs7_pad(b, 4)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_zero_blksize_raises(self):
        b = b'YELLOW SUBMARINE'

        with self.assertRaises(InvalidPaddingException):
            pkcs7_pad(b, 0)

    def test_pkcs7_pad_negative_blksize_raises(self):
        b = b'YELLOW SUBMARINE'

        with self.assertRaises(InvalidPaddingException):
            pkcs7_pad(b, -1)

    def test_pkcs7_pad_blksize_over_bounds_raises(self):
        b = b'YELLOW SUBMARINE'

        with self.assertRaises(InvalidPaddingException):
            pkcs7_pad(b, 256)

    def test_pkcs7_pad_cryptopals_case(self):
        b = b"YELLOW SUBMARINE"
        expected_padded = b"YELLOW SUBMARINE\x04\x04\x04\x04"

        actual_padded = pkcs7_pad(b, 20)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_pad_bytes_size_mutliple_of_blksize_adds_extra_block(self):
        b = b"YELLOW"
        expected_padded = b"YELLOW\x03\x03\x03"

        actual_padded = pkcs7_pad(b, 3)

        self.assertEqual(expected_padded, actual_padded)

    def test_pkcs7_unpad_empty_bytes_returns_empty(self):
        padded = b""
        expected_bytes = b""

        actual_bytes = pkcs7_unpad(padded)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_pkcs7_unpad_all_padding_returns_empty(self):
        padded = b"\x04\x04\x04\x04"
        expected_bytes = b""

        actual_bytes = pkcs7_unpad(padded)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_pkcs7_unpad_cryptopals_case(self):
        padded = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        expected_bytes = b"YELLOW SUBMARINE"

        actual_bytes = pkcs7_unpad(padded)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_pkcs7_unpad_whole_block_padding(self):
        padded = b"YELLOW\x03\x03\x03"
        expected_bytes = b"YELLOW"

        actual_bytes = pkcs7_unpad(padded)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_pkcs7_unpad_padding_value_larger_than_valid_raises(self):
        padded = b"YELLOW\x16\x16\x16"

        with self.assertRaises(InvalidPaddingException):
            pkcs7_unpad(padded)

    def test_pkcs7_unpad_padding_value_incosistent(self):
        padded = b"ICE ICE BABY\x01\x02\x03\x04"

        with self.assertRaises(InvalidPaddingException):
            pkcs7_unpad(padded)

    def test_pkcs7_unpad_padding_value_does_not_match_number_of_pads(self):
        padded = b"ICE ICE BABY\x05\x05\x05\x05"

        with self.assertRaises(InvalidPaddingException):
            pkcs7_unpad(padded)

    def test_pkcs7_unpad_padding_ending_with_zero_raises(self):
        padded = b"YELLOW\x00"

        with self.assertRaises(InvalidPaddingException):
            pkcs7_unpad(padded)
