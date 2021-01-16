import base64
import os
import pathlib
import unittest

from set1.challenge6.break_repeat_xor import *


class TestHammingDistance(unittest.TestCase):

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


class TestBreakRepeatXOR(unittest.TestCase):

    def test_find_keysize_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            find_keysize(None)

    def test_find_keysize_negative_num_blks_returns_empty(self):
        b = b'Hey'
        expected_keysizes = []

        actual_keysizes = find_keysize(b, num_blks=-1)

        self.assertEqual(expected_keysizes, actual_keysizes)

    def test_find_keysize_zero_num_blks_returns_empty(self):
        b = b'Hey'
        expected_keysizes = []

        actual_keysizes = find_keysize(b, num_blks=0)

        self.assertEqual(expected_keysizes, actual_keysizes)

    def test_find_keysize_invalid_max_keysize_returns_empty(self):
        b = b'Hey'
        expected_keysizes = []

        actual_keysizes = find_keysize(b, max_keysize=0)

        self.assertEqual(expected_keysizes, actual_keysizes)

    def test_find_keysize_cryptopals_case(self):
        input_filename = os.path.join(
            pathlib.Path(__file__).parent.parent,
            "input"
        )
        with open(input_filename, 'r') as input_file:
            base64_str = input_file.read()
        base64_bytes = base64_str.replace('\n', '').encode("utf-8")
        b = base64.decodebytes(base64_bytes)
        expected_keysize = 29

        actual_keysizes = find_keysize(b)

        self.assertEqual(expected_keysize, actual_keysizes[0])
