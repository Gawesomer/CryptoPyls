import unittest

from set2.challenge12.ecb_decrypt import *


class TestECBDecrypt(unittest.TestCase):

    def test_determine_blksize_aes128(self):
        encryption_oracle = gen_encryption_oracle(16)

        self.assertEqual(16, determine_blksize(encryption_oracle))

    def test_determine_blksize_aes256(self):
        encryption_oracle = gen_encryption_oracle(32)

        self.assertEqual(32, determine_blksize(encryption_oracle))
