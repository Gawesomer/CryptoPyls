import unittest

from set2.challenge11.rand_enc import *


class TestRandEnc(unittest.TestCase):

    def test_rand_key_gen_zero_keysize_returns_empty_bytes(self):
        self.assertEqual(b'', rand_key_gen(0))

    def test_rand_key_gen_negative_keysize_returns_empty_bytes(self):
        self.assertEqual(b'', rand_key_gen(-1))

    def test_rand_key_gen_nominal_case(self):
        key = rand_key_gen(16)

        self.assertEqual(16, len(key))
