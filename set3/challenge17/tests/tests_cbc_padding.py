from Crypto.Cipher import AES
import unittest
import sys

from set2.challenge10.cbc_mode import CBCMode
from set3.challenge17.cbc_padding import \
    CONSISTENT_KEY, \
    break_cbc_single_blk, \
    encryption_oracle, \
    get_byte_n, \
    valid_padding


class TestCBCPadding(unittest.TestCase):

    def test_valid_padding_integration_padding_is_valid(self):
        encrypted, iv = encryption_oracle()

        self.assertTrue(valid_padding(encrypted, iv))

    def test_valid_padding_padding_is_invalid(self):
        encrypted, iv = encryption_oracle()
        encrypted = encrypted[:-1] + \
            ((encrypted[-1]+1) % 256).to_bytes(1, byteorder=sys.byteorder)

        self.assertFalse(valid_padding(encrypted, iv))

    def test_get_byte_n_empty_bytes_raises(self):
        with self.assertRaises(IndexError):
            get_byte_n(b'', 0)

    def test_get_byte_n_nominal_case(self):
        b = b'123'

        self.assertEqual(b'3', get_byte_n(b, 2))

    def test_get_byte_n_negative_indexing(self):
        b = b'123'

        self.assertEqual(b'3', get_byte_n(b, -1))

    def test_get_byte_n_n_too_large_raises(self):
        with self.assertRaises(IndexError):
            get_byte_n(b'123', 3)

    def test_get_byte_n_n_too_small_raises(self):
        with self.assertRaises(IndexError):
            get_byte_n(b'123', -4)

    def test_break_cbc_single_blk_nominal_case(self):
        plain = b"YELLOW SUBMARINE"
        iv = b"abcdefghijklmnop"

        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
        cbc = CBCMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            iv=iv
        )
        encrypted = cbc.encrypt(plain)

        decrypted = break_cbc_single_blk(iv, encrypted, valid_padding)

        self.assertEqual(plain, decrypted)
