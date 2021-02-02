import unittest

from set2.challenge11.rand_enc import rand_bytes_gen
from set3.challenge24.break_mt19937_cipher import gen_ciphertext, recover_key


class TestBreakMT19937StreamCipher(unittest.TestCase):

    def test_recover_key_nominal_case(self):
        seed = int.from_bytes(rand_bytes_gen(1), "little")
        known_plaintext = b'A' * 14
        ciphertext = gen_ciphertext(known_plaintext, seed)

        recovered_seed = recover_key(known_plaintext, ciphertext, 8)

        self.assertEqual(seed, recovered_seed)
