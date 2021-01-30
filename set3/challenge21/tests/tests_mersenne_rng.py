import unittest

from set3.challenge21.mersenne_rng import get_n_lowest_bits, MT19937


class TestGetBits(unittest.TestCase):

    def test_get_n_lowest_bits_zero(self):
        self.assertEqual(0, get_n_lowest_bits(0, 32))

    def test_get_n_lowest_bits_nominal_case(self):
        self.assertEqual(12, get_n_lowest_bits(172, 4))

    def test_get_n_lowest_bits_0b_prefix_is_ignored(self):
        self.assertEqual(15, get_n_lowest_bits(15, 5))

    def test_get_n_lowest_bits_zero_n_returns_zero(self):
        self.assertEqual(0, get_n_lowest_bits(1, 0))

    def test_get_n_lowest_bits_negative_n_raise(self):
        with self.assertRaises(ValueError):
            get_n_lowest_bits(15, -1)


class TestMT19937(unittest.TestCase):

    def test_extract_number_without_seeding_raises(self):
        mt = MT19937()
        with self.assertRaises(Exception):
            mt.extract_number()

    def test_extract_number_nominal_case(self):
        # Expected numbers generated from MT19937 with a seed of 123
        # obtained from: https://asecuritysite.com/encryption/twister
        expected_numbers = (
            2991312382,
            3062119789,
            1228959102,
            1840268610,
            974319580,
        )

        mt = MT19937()
        mt.seed_mt(123)
        for expected in expected_numbers:
            self.assertEqual(expected, mt.extract_number())
