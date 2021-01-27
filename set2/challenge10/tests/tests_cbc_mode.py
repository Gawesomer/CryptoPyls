from Crypto.Cipher import AES
import unittest
import sys

from set2.challenge10.cbc_mode import *


class TestCBCMode(unittest.TestCase):

    def mock_fun(self, b: bytes) -> bytes:
        operand = b''
        for i in range(len(b)):
            operand += i.to_bytes(1, byteorder=sys.byteorder)
        return xor(b, operand)

    def test_init_iv_bigger_than_blksize_raises(self):
        iv = b"\x03\x03\x23"

        with self.assertRaises(ValueError):
            CBCMode(
                blksize=2,
                encrypt_blk=self.mock_fun,
                decrypt_blk=self.mock_fun,
                iv=iv,
            )

    def test_init_iv_smaller_than_blksize_returns_empty_bytes(self):
        iv = b"\x03"

        with self.assertRaises(ValueError):
            CBCMode(
                blksize=2,
                encrypt_blk=self.mock_fun,
                decrypt_blk=self.mock_fun,
                iv=iv,
            )

    def test_encrypt_bytes_of_proper_length(self):
        b = b"\x00\x01\x00\x01"
        iv = b"\x03\x03"
        expected_bytes = b"\x03\x03\x03\x03"

        cbc = CBCMode(
            blksize=2,
            encrypt_blk=self.mock_fun,
            decrypt_blk=self.mock_fun,
            iv=iv,
        )
        actual_bytes = cbc.encrypt(b)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_encrypt_bytes_not_padded_raises(self):
        b = b"\x00\x01\x00\x01\x23"
        iv = b"\x03\x03"
        cbc = CBCMode(
            blksize=2,
            encrypt_blk=self.mock_fun,
            decrypt_blk=self.mock_fun,
            iv=iv,
        )

        with self.assertRaises(ValueError):
            cbc.encrypt(b)

    def test_decrypt_bytes_not_padded_raises(self):
        b = b"\x00\x01\x00\x01\x23"
        iv = b"\x03\x03"
        cbc = CBCMode(
            blksize=2,
            encrypt_blk=self.mock_fun,
            decrypt_blk=self.mock_fun,
            iv=iv,
        )

        with self.assertRaises(ValueError):
            cbc.decrypt(b)

    def test_encrypt_decrypt_integration_case(self):
        key = b"YELLOW SUBMARINE"
        iv = b"THIS IS 16 BYTES"
        cipher = AES.new(key, AES.MODE_ECB)
        cbc = CBCMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            iv=iv,
        )
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elitAAAAAAAAA")

        encrypted = cbc.encrypt(plaintext)
        decrypted = cbc.decrypt(encrypted)

        self.assertEqual(plaintext, decrypted)
