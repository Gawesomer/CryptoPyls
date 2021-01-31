import unittest

from set3.challenge21.mersenne_rng import MT19937
from set3.challenge23.clone_mt19937 import \
    _untemper_right, \
    _untemper_left, \
    untemper, \
    get_numbits, \
    keep_bitrange


class TestBitArithmetic(unittest.TestCase):

    def test_get_numbits_nominal_case(self):
        self.assertEqual(7, get_numbits(123))

    def test_get_numbits_zero_returns_zero(self):
        self.assertEqual(0, get_numbits(0))

    def test_get_numbits_negative_returns_zero(self):
        self.assertEqual(0, get_numbits(-1))

    def test_keep_bitrange_keep_midle_bits(self):
        self.assertEqual(0xA0, keep_bitrange(0xFAF, 5, 8))

    def test_keep_bitrange_keep_first_bits(self):
        self.assertEqual(0xA00, keep_bitrange(0xAFF, 9, 12))

    def test_keep_bitrange_keep_last_bits(self):
        self.assertEqual(0xA, keep_bitrange(0xFFA, 1, 4))

    def test_keep_bitrange_negative_low_raises(self):
        with self.assertRaises(ValueError):
            keep_bitrange(0xABC, -1, 1)

    def test_keep_bitrange_zero_low_raises(self):
        with self.assertRaises(ValueError):
            keep_bitrange(0xABC, 0, 1)

    def test_keep_bitrange_high_smaller_than_low_raises(self):
        with self.assertRaises(ValueError):
            keep_bitrange(0xABC, 2, 1)

    def test_keep_bitrange_low_equal_high_keeps_single_bit(self):
        self.assertEqual(0x80, keep_bitrange(0xFAF, 8, 8))

    def test_keep_bitrange_range_exceeds_input_returns_zero(self):
        self.assertEqual(0, keep_bitrange(0xA, 9, 12))


class TestCloneMT19937(unittest.TestCase):

    def temper_right(self, bits: int, shift: int, mask: int) -> int:
        """ XOR `bits` against a right shifted value """
        return bits ^ ((bits >> shift) & mask)

    def temper_left(self, bits: int, shift: int, mask: int) -> int:
        """ XOR `bits` against a left shifted value """
        return bits ^ ((bits << shift) & mask)

    def temper_mt19937(self, bits) -> int:
        """ tempering method from MT19937 """
        b = 0x9D2C5680
        c = 0xEFC60000
        s = 7
        t = 15
        u = 11
        d = 0xFFFFFFFF
        l = 18

        bits = bits ^ ((bits >> u) & d)
        bits = bits ^ ((bits << s) & b)
        bits = bits ^ ((bits << t) & c)
        bits = bits ^ (bits >> l)

        return bits

    def test_untemper_right_negative_shift_raises(self):
        with self.assertRaises(ValueError):
            _untemper_right(12, -1, 7)

    def test_untemper_right_smaller_than_bitshift(self):
        bits = 12
        shift = 4
        mask = 7
        tempered = self.temper_right(bits, shift, mask)

        untempered = _untemper_right(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_right_shift_half_bitsize(self):
        bits = 0xE
        shift = 2
        mask = 0x1
        tempered = self.temper_right(bits, shift, mask)

        untempered = _untemper_right(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_right_last_shift_results_in_smaller_block(self):
        bits = 0x1D
        shift = 2
        mask = 0x1
        tempered = self.temper_right(bits, shift, mask)

        untempered = _untemper_right(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_right_invert_tempering_without_and_mask(self):
        expected = 172233979
        tempered = 172234346    # y ^ (y >> l)

        untempered = _untemper_right(
            tempered,
            18,
            (1 << get_numbits(tempered)) - 1
        )

        self.assertEqual(expected, untempered)

    def test_untemper_left_negative_shift_raise(self):
        with self.assertRaises(ValueError):
            _untemper_left(12, -1, 7)

    def test_untemper_left_smaller_than_bitshift(self):
        bits = 12
        shift = 4
        mask = 7
        tempered = self.temper_left(bits, shift, mask)

        untempered = _untemper_left(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_left_last_shift_results_in_smaller_block(self):
        bits = 0x1D
        shift = 2
        mask = 0x4
        tempered = self.temper_left(bits, shift, mask)

        untempered = _untemper_left(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_left_regression_case(self):
        bits = 0x5A96E158
        shift = 15
        mask = 0xEFC60000
        tempered = self.temper_left(bits, shift, mask)

        untempered = _untemper_left(tempered, shift, mask)

        self.assertEqual(bits, untempered)

    def test_untemper_nominal_case(self):
        mt = MT19937()
        mt.seed_mt(123)

        self.assertEqual(untemper(mt.extract_number()), mt.MT[0])
        self.assertEqual(untemper(mt.extract_number()), mt.MT[1])
        self.assertEqual(untemper(mt.extract_number()), mt.MT[2])
        self.assertEqual(untemper(mt.extract_number()), mt.MT[3])
        self.assertEqual(untemper(mt.extract_number()), mt.MT[4])
