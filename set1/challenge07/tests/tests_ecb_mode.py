from Crypto.Cipher import AES
import unittest
import sys

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import *


class TestBlocks(unittest.TestCase):

    def test_get_block_n_get_first_block(self):
        b = b"ABCDEF"
        expected_block = b"AB"

        actual_block = get_block_n(b, 2, 0)

        self.assertEqual(expected_block, actual_block)

    def test_get_block_n_get_middle_block(self):
        b = b"ABCDEF"
        expected_block = b"CD"

        actual_block = get_block_n(b, 2, 1)

        self.assertEqual(expected_block, actual_block)

    def test_get_block_n_get_last_block_of_size_blksize(self):
        b = b"ABCDEF"
        expected_block = b"EF"

        actual_block = get_block_n(b, 2, 2)

        self.assertEqual(expected_block, actual_block)

    def test_get_block_n_get_last_block_smaller_than_blksize(self):
        b = b"ABCDE"
        expected_block = b"E"

        actual_block = get_block_n(b, 2, 2)

        self.assertEqual(expected_block, actual_block)

    def test_get_block_n_n_larger_than_numblks_returns_empty(self):
        b = b"ABCDEF"
        expected_block = b""

        actual_block = get_block_n(b, 2, 3)

        self.assertEqual(expected_block, actual_block)

    def test_get_block_n_negative_n_returns_empty(self):
        b = b"ABCDEF"
        expected_block = b""

        actual_block = get_block_n(b, 2, -1)

        self.assertEqual(expected_block, actual_block)

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


class TestECBMode(unittest.TestCase):

    def mock_fun(self, b: bytes) -> bytes:
        operand = b''
        for i in range(len(b)):
            operand += i.to_bytes(1, byteorder=sys.byteorder)
        return xor(b, operand)

    def test_init_zero_blksize_raises(self):
        with self.assertRaises(ValueError):
            ECBMode(0, self.mock_fun, self.mock_fun)

    def test_init_negative_blksize_raises(self):
        with self.assertRaises(ValueError):
            ECBMode(-1, self.mock_fun, self.mock_fun)

    def test_encrypt_none_bytes_raises_typeerror(self):
        ecb = ECBMode(1, self.mock_fun, self.mock_fun)
        with self.assertRaises(TypeError):
            ecb.encrypt(None)

    def test_encrypt_bytes_of_proper_length(self):
        ecb = ECBMode(2, self.mock_fun, self.mock_fun)
        b = b"\x00\x01\x00\x01"
        expected_bytes = b"\x00\x00\x00\x00"

        actual_bytes = ecb.encrypt(b)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_encrypt_bytes_not_padded_raises(self):
        ecb = ECBMode(2, self.mock_fun, self.mock_fun)
        b = b"\x00\x01\x00\x01\x23"

        with self.assertRaises(ValueError):
            actual_bytes = ecb.encrypt(b)

    def test_decrypt_bytes_not_padded_raises(self):
        ecb = ECBMode(2, self.mock_fun, self.mock_fun)
        b = b"\x00\x01\x00\x01\x23"

        with self.assertRaises(ValueError):
            actual_bytes = ecb.decrypt(b)

    def test_encrypt_decrypt_integration(self):
        key = b"YELLOW SUBMARINE"
        cipher = AES.new(key, AES.MODE_ECB)
        ecb = ECBMode(16, cipher.encrypt, cipher.decrypt)
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elitAAAAAAAAA")

        encrypted = ecb.encrypt(plaintext)
        decrypted = ecb.decrypt(encrypted)

        self.assertEqual(plaintext, decrypted)
