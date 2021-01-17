import unittest
import sys

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import *


class TestECBMode(unittest.TestCase):

    def mock_fun(self, b: bytes) -> bytes:
        operand = b''
        for i in range(len(b)):
            operand += i.to_bytes(1, byteorder=sys.byteorder)
        return xor(b, operand)

    def test_blocks_zero_blksize_returns_empty_bytes(self):
        b = b"ABCDEF"
        expected_blocks = [b'']

        for i, block in enumerate(blocks(b, 0)):
            self.assertEqual(expected_blocks[i], block)

    def test_blocks_negative_blksize_returns_empty_bytes(self):
        b = b"ABCDEF"
        expected_blocks = [b'']

        for i, block in enumerate(blocks(b, -1)):
            self.assertEqual(expected_blocks[i], block)

    def test_blocks_bytes_of_proper_length(self):
        b = b"ABCDEF"
        expected_blocks = [b"AB", b"CD", b"EF"]

        for i, block in enumerate(blocks(b, 2)):
            self.assertEqual(expected_blocks[i], block)

    def test_blocks_bytes_not_padded_ignores_extraneous(self):
        b = b"ABCDEFG"
        expected_blocks = [b"AB", b"CD", b"EF"]

        for i, block in enumerate(blocks(b, 2)):
            self.assertEqual(expected_blocks[i], block)

    def test_ecb_mode_none_bytes_raises_typeerror(self):
        with self.assertRaises(TypeError):
            ecb_mode(None, 1, self.mock_fun)

    def test_ecb_mode_zero_blksize_returns_empty_bytes(self):
        b = b"\x00\x01\x00\x01"
        expected_bytes = b''

        actual_bytes = ecb_mode(b, 0, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_ecb_mode_negative_blksize_returns_empty_bytes(self):
        b = b"\x00\x01\x00\x01"
        expected_bytes = b''

        actual_bytes = ecb_mode(b, -1, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_ecb_mode_bytes_of_proper_length(self):
        b = b"\x00\x01\x00\x01"
        expected_bytes = b"\x00\x00\x00\x00"

        actual_bytes = ecb_mode(b, 2, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_ecb_mode_bytes_not_padded_ignores_extraneous(self):
        b = b"\x00\x01\x00\x01\x23"
        expected_bytes = b"\x00\x00\x00\x00"

        actual_bytes = ecb_mode(b, 2, self.mock_fun)

        self.assertEqual(expected_bytes, actual_bytes)
