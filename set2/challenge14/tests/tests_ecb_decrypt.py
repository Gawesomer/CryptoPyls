import unittest

from set2.challenge11.rand_enc import rand_bytes_gen
from set2.challenge14.ecb_decrypt import break_ecb, determine_randbytes_size, \
    gen_encryption_oracle


class TestECBDecrypt(unittest.TestCase):

    def test_determine_randbytes_size_nominal_case(self):
        randbytes = rand_bytes_gen(47)
        encryption_oracle = gen_encryption_oracle(16, randbytes=randbytes)

        randbytes_size = determine_randbytes_size(encryption_oracle, 16)

        self.assertEqual(47, randbytes_size)

    def test_determine_randbytes_size_multiple_of_blksize(self):
        randbytes = rand_bytes_gen(32)
        encryption_oracle = gen_encryption_oracle(16, randbytes=randbytes)

        randbytes_size = determine_randbytes_size(encryption_oracle, 16)

        self.assertEqual(32, randbytes_size)

    def test_determine_randbytes_size_less_than_one_block_randbytes(self):
        randbytes = rand_bytes_gen(7)
        encryption_oracle = gen_encryption_oracle(16, randbytes=randbytes)

        randbytes_size = determine_randbytes_size(encryption_oracle, 16)

        self.assertEqual(7, randbytes_size)

    def test_determine_randbytes_size_zero_randbytes(self):
        encryption_oracle = gen_encryption_oracle(16, randbytes=b'')

        randbytes_size = determine_randbytes_size(encryption_oracle, 16)

        self.assertEqual(0, randbytes_size)

    def test_break_ecb_nominal_case(self):
        unknownstr = b"YELLOW SUBMARINEEXTRA"
        randbytes = rand_bytes_gen(47)
        encryption_oracle = gen_encryption_oracle(16, unknownstr, randbytes)

        self.assertEqual(unknownstr, break_ecb(encryption_oracle))

    def test_break_ecb_randbytes_size_multiple_of_blksize(self):
        unknownstr = b"YELLOW SUBMARINEEXTRA"
        randbytes = rand_bytes_gen(32)
        encryption_oracle = gen_encryption_oracle(16, unknownstr, randbytes)

        self.assertEqual(unknownstr, break_ecb(encryption_oracle))

    def test_break_ecb_randbytes_less_than_one_block_randbytes(self):
        unknownstr = b"YELLOW SUBMARINEEXTRA"
        randbytes = rand_bytes_gen(7)
        encryption_oracle = gen_encryption_oracle(16, unknownstr, randbytes)

        self.assertEqual(unknownstr, break_ecb(encryption_oracle))

    def test_break_ecb_randbytes_zero_randbytes(self):
        unknownstr = b"YELLOW SUBMARINEEXTRA"
        randbytes = rand_bytes_gen(7)
        encryption_oracle = gen_encryption_oracle(16, unknownstr, randbytes)

        self.assertEqual(unknownstr, break_ecb(encryption_oracle))
