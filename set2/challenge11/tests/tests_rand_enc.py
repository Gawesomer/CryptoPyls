import unittest

from set2.challenge11.rand_enc import gen_encryption_oracle, is_ecb, \
    rand_bytes_gen


class TestRandEnc(unittest.TestCase):

    def test_rand_bytes_gen_zero_keysize_returns_empty_bytes(self):
        self.assertEqual(b'', rand_bytes_gen(0))

    def test_rand_bytes_gen_negative_keysize_returns_empty_bytes(self):
        self.assertEqual(b'', rand_bytes_gen(-1))

    def test_rand_bytes_gen_nominal_case(self):
        key = rand_bytes_gen(16)

        self.assertEqual(16, len(key))

    def test_is_ecb_detects_ecb_mode(self):
        encryption_oracle = gen_encryption_oracle(16, True)

        self.assertTrue(is_ecb(encryption_oracle, 16))

    def test_is_ecb_detects_non_ecb_mode(self):
        encryption_oracle = gen_encryption_oracle(16, use_ecb=False)

        self.assertFalse(is_ecb(encryption_oracle, 16))
