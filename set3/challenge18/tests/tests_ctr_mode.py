from Crypto.Cipher import AES
import unittest
import sys

from set3.challenge18.ctr_mode import *


class TestCTRMode(unittest.TestCase):

    def test_default_counter_nominal_case(self):
        expected = [i for i in range(10)]
        actual = []

        for i in CTRMode.default_counter():
            actual.append(i)
            if i == 9:
                break

        self.assertEqual(expected, actual)

    def test_default_combine_zero_blksize_raises(self):
        with self.assertRaises(ValueError):
            CTRMode.default_combine(b'', 0, 0)

    def test_default_combine_nonce_half_blksize(self):
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected_blk = (b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x01\x00\x00\x00\x00\x00\x00\x00")

        actual_blk = CTRMode.default_combine(nonce, 1, 16)

        self.assertEqual(expected_blk, actual_blk)

    def test_default_combine_nonce_less_than_half_blksize_gets_padded(self):
        nonce = b"\x00\x00\x00\x00"
        expected_blk = (b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x01\x00\x00\x00\x00\x00\x00\x00")

        actual_blk = CTRMode.default_combine(nonce, 1, 16)

        self.assertEqual(expected_blk, actual_blk)

    def test_default_combine_nonce_more_than_half_blksize_gets_cut(self):
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00EXTRA"
        expected_blk = (b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x01\x00\x00\x00\x00\x00\x00\x00")

        actual_blk = CTRMode.default_combine(nonce, 1, 16)

        self.assertEqual(expected_blk, actual_blk)

    def test_default_combine_blkcount_uses_little_endian(self):
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected_blk = (b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x01\x00\x00\x00\x00\x00\x00")

        actual_blk = CTRMode.default_combine(nonce, 256, 16)

        self.assertEqual(expected_blk, actual_blk)

    def test_default_combine_blkcount_too_large_raises(self):
        with self.assertRaises(OverflowError):
            CTRMode.default_combine(b'', pow(2, 8*8), 16)

    def test_encrypt_nominal_case(self):
        key = b"YELLOW SUBMARINE"
        nonce = bytes(8)
        cipher = AES.new(key, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=nonce,
        )
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elitAAAAAAAAA")
        expected_encrypted = (b":\xbe\xb9.\xc2\x82/\x92\x90\xdan}\x08|\xaf\x1d"
                              b"\xa0\xcc\x1f\xb5\xecMs\xb3\xaa\xae3\xb3\xcc\x81\x1dk"
                              b"H\xc3\xfa\xaee\x0eEk\xa2\xbe\xdeV\xdb\x8f\xe7\xa4"
                              b"\xaf\xe7\x8bP%\x93\x1a\x14\x90\r'&\x88.\xe4\xf1")

        encrypted = ctr.encrypt(plaintext)

        self.assertEqual(expected_encrypted, encrypted)

    def test_encrypt_unpadded_plaintext(self):
        key = b"YELLOW SUBMARINE"
        nonce = bytes(8)
        cipher = AES.new(key, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=nonce,
        )
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elit")
        expected_encrypted = (b":\xbe\xb9.\xc2\x82/\x92\x90\xdan}\x08|\xaf\x1d"
                              b"\xa0\xcc\x1f\xb5\xecMs\xb3\xaa\xae3\xb3\xcc\x81\x1dk"
                              b"H\xc3\xfa\xaee\x0eEk\xa2\xbe\xdeV\xdb\x8f\xe7\xa4"
                              b"\xaf\xe7\x8bP%\x93\x1a")

        encrypted = ctr.encrypt(plaintext)

        self.assertEqual(expected_encrypted, encrypted)

    def test_decrypt_nominal_case(self):
        key = b"YELLOW SUBMARINE"
        nonce = bytes(8)
        cipher = AES.new(key, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=nonce,
        )
        encrypted = (b":\xbe\xb9.\xc2\x82/\x92\x90\xdan}\x08|\xaf\x1d"
                     b"\xa0\xcc\x1f\xb5\xecMs\xb3\xaa\xae3\xb3\xcc\x81\x1dk"
                     b"H\xc3\xfa\xaee\x0eEk\xa2\xbe\xdeV\xdb\x8f\xe7\xa4"
                     b"\xaf\xe7\x8bP%\x93\x1a\x14\x90\r'&\x88.\xe4\xf1")
        expected_plaintext = (b"Lorem ipsum dolo"
                              b"r sit amet, cons"
                              b"ectetur adipisci"
                              b"ng elitAAAAAAAAA")

        decrypted = ctr.decrypt(encrypted)

        self.assertEqual(expected_plaintext, decrypted)

    def test_decrypt_unpadded_plaintext(self):
        key = b"YELLOW SUBMARINE"
        nonce = bytes(8)
        cipher = AES.new(key, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=nonce,
        )
        encrypted = (b":\xbe\xb9.\xc2\x82/\x92\x90\xdan}\x08|\xaf\x1d"
                     b"\xa0\xcc\x1f\xb5\xecMs\xb3\xaa\xae3\xb3\xcc\x81\x1dk"
                     b"H\xc3\xfa\xaee\x0eEk\xa2\xbe\xdeV\xdb\x8f\xe7\xa4"
                     b"\xaf\xe7\x8bP%\x93\x1a")
        expected_plaintext = (b"Lorem ipsum dolo"
                              b"r sit amet, cons"
                              b"ectetur adipisci"
                              b"ng elit")

        decrypted = ctr.decrypt(encrypted)

        self.assertEqual(expected_plaintext, decrypted)
