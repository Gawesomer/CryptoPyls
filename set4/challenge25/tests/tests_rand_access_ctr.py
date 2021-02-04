from Crypto.Cipher import AES
import unittest

from set3.challenge18.ctr_mode import CTRMode
from set4.challenge25.rand_access_ctr import break_rand_access_ctr, \
    gen_edit_oracle


class TestRandAccessCTR(unittest.TestCase):

    def setUp(self):
        self.plaintext = b"Hello World!"

        self.key = b"YELLOW SUBMARINE"
        self.nonce = bytes(8)
        cipher = AES.new(self.key, AES.MODE_ECB)
        self.ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=self.nonce,
        )
        self.ciphertext = self.ctr.encrypt(self.plaintext)
        self.edit_oracle = gen_edit_oracle(self.key, self.nonce)

    def test_edit_oracle_zero_offset_prepends(self):
        newtext = b"What?"
        expected_plaintext = newtext + self.plaintext

        new_ciphertext = self.edit_oracle(self.ciphertext, 0, newtext)
        decrypted = self.ctr.decrypt(new_ciphertext)

        self.assertEqual(expected_plaintext, decrypted)

    def test_edit_oracle_negative_offset_inserts_using_negative_indexing(self):
        newtext = b"What?"
        expected_plaintext = b"Hello WorWhat?ld!"

        new_ciphertext = self.edit_oracle(self.ciphertext, -3, newtext)
        decrypted = self.ctr.decrypt(new_ciphertext)

        self.assertEqual(expected_plaintext, decrypted)

    def test_edit_oracle_index_too_large_appends(self):
        newtext = b"What?"
        expected_plaintext = self.plaintext + newtext

        new_ciphertext = self.edit_oracle(self.ciphertext, 100, newtext)
        decrypted = self.ctr.decrypt(new_ciphertext)

        self.assertEqual(expected_plaintext, decrypted)

    def test_edit_oracle_nominal_case(self):
        newtext = b"What?"
        expected_plaintext = b"HellWhat?o World!"

        new_ciphertext = self.edit_oracle(self.ciphertext, 4, newtext)
        decrypted = self.ctr.decrypt(new_ciphertext)

        self.assertEqual(expected_plaintext, decrypted)

    def test_break_rand_access_ctr_nominal_case(self):
        decrypted = break_rand_access_ctr(self.ciphertext, self.edit_oracle)

        self.assertEqual(self.plaintext, decrypted)
