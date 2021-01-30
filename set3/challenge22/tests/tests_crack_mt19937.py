import unittest
import time

from set3.challenge21.mersenne_rng import MT19937
from set3.challenge22.crack_mt19937 import break_currtime_mt19937


class TestBreakCurrTimeMT19937(unittest.TestCase):

    def test_break_currtime_mt19937_nominal_case(self):
        actual_seed = int(time.time())

        mt = MT19937()
        mt.seed_mt(actual_seed)
        cracked_seed = break_currtime_mt19937(mt.extract_number(), eps=10)

        self.assertEqual(actual_seed, cracked_seed)

    def test_break_currtime_mt19937_seed_outside_search_range_returns_none(self):
        actual_seed = int(time.time())-100

        mt = MT19937()
        mt.seed_mt(actual_seed)

        self.assertIsNone(break_currtime_mt19937(mt.extract_number(), eps=10))
