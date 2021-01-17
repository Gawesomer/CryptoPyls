import unittest
import sys

from set2.challenge10.cbc_mode import *


class TestCBCMode(unittest.TestCase):

    def mock_fun(self, b: bytes) -> bytes:
        operand = b''
        for i in range(len(b)):
            operand += i.to_bytes(1, byteorder=sys.byteorder)
        return xor(b, operand)

    def test_cbc_mode_zero_blksize_return_empty_bytes(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03\x03"
        expected_bytes = b''

        actual_bytes = cbc_mode(b, 0, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_cbc_mode_negative_blksize_returns_empty_bytes(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03\x03"
        expected_bytes = b''

        actual_bytes = cbc_mode(b, -1, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_cbc_mode_bytes_of_proper_length(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03\x03"
        expected_bytes = b"\x03\x03\x03\x03"

        actual_bytes = cbc_mode(b, 2, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_cbc_mode_bytes_not_padded_ignores_extraneous(self):
        b = b"\x00\x01\x00\x01\x23"
        iv = b"\x03\x03"
        expected_bytes = b"\x03\x03\x03\x03"

        actual_bytes = cbc_mode(b, 2, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_cbc_mode_iv_bigger_than_blksize_ignores_extraneous(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03\x03\x23"
        expected_bytes = b"\x03\x03\x03\x03"

        actual_bytes = cbc_mode(b, 2, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_cbc_mode_iv_smaller_than_blksize_returns_empty_bytes(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03"
        expected_bytes = b''

        actual_bytes = cbc_mode(b, 2, iv, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)
