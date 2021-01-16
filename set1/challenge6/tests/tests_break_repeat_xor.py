import unittest

from set1.challenge6.break_repeat_xor import *


class TestBreakRepeatXOR(unittest.TestCase):

    def test_hamming_dist_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            hamming_dist(None, None)

    def test_hamming_dist_empty_returns_zero(self):
        self.assertEqual(hamming_dist(b'', b''), 0)

    def test_hamming_dist_equal_bytes_returns_zero(self):
        b = b"this is a test"

        self.assertEqual(hamming_dist(b, b), 0)

    def test_hamming_dist_cryptopals_case(self):
        b1 = b"this is a test"
        b2 = b"wokka wokka!!!"

        self.assertEqual(hamming_dist(b1, b2), 37)
