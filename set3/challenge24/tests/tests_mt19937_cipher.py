import unittest

from set3.challenge21.mersenne_rng import MT19937
from set3.challenge24.mt19937_cipher import MT19937Cipher


class TestMT19937StreamCipher(unittest.TestCase):

    def test_default_gen_key_verify_first_two_random_numbers(self):
        expected_ints = [254, 205, 75, 178, 109, 61, 132, 182]
        mt = MT19937()
        mt.seed_mt(123)

        actual_ints = []
        i = 0
        for b in MT19937Cipher.default_gen_key(mt):
            actual_ints.append(b)
            i += 1
            if i == 8:
                break

        self.assertEqual(expected_ints, actual_ints)

    def test_encrypt_nominal_case(self):
        seed = 123
        cipher = MT19937Cipher(seed=seed)
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elit")
        expected_encrypted = (b"\xb2\xa29\xd7\x00\x1d\xed\xc6\r\x18-i&*\xdc"
                              b"\x02\xae\xcfaS\x16\xf4\xbc\xdd\x83\x82\x0e\xad"
                              b"rSt\xcb6}[\xdd\x1e\x8d\xcb]\x1a\xd09\x1cP\x95"
                              b"\xcc\xae\xb8;3\x9e\x8d?F")

        encrypted = cipher.encrypt(plaintext)

        self.assertEqual(expected_encrypted, encrypted)

    def test_decrypt_nominal_case(self):
        seed = 123
        cipher = MT19937Cipher(seed=seed)
        encrypted = (b"\xb2\xa29\xd7\x00\x1d\xed\xc6\r\x18-i&*\xdc"
                     b"\x02\xae\xcfaS\x16\xf4\xbc\xdd\x83\x82\x0e\xad"
                     b"rSt\xcb6}[\xdd\x1e\x8d\xcb]\x1a\xd09\x1cP\x95"
                     b"\xcc\xae\xb8;3\x9e\x8d?F")
        expected_plaintext = (b"Lorem ipsum dolo"
                              b"r sit amet, cons"
                              b"ectetur adipisci"
                              b"ng elit")

        decrypted = cipher.decrypt(encrypted)

        self.assertEqual(expected_plaintext, decrypted)

    def test_encrypt_decrypt_integration(self):
        seed = 123
        cipher = MT19937Cipher(seed=seed)
        plaintext = (b"Lorem ipsum dolo"
                     b"r sit amet, cons"
                     b"ectetur adipisci"
                     b"ng elit")

        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)

        self.assertEqual(plaintext, decrypted)
