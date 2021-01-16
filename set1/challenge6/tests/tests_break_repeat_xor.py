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

    def test_find_keysize_short_message_ignores_keysizes_too_large(self):
        b = b'ABCD'

        actual_keysizes = find_keysize(b, num_blks=2, max_keysize=40)

        self.assertEqual(2, len(actual_keysizes))

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

    def test_build_transposed_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            build_transposed(None, 1, 1)

    def test_build_transposed_empty_input_returns_empty(self):
        self.assertEqual(build_transposed(b'', 1, 1), b'')

    def test_build_transposed_mod_one_returns_given_bytes(self):
        b = b'Hey there'
        expected_bytes = b'Hey there'

        actual_bytes = build_transposed(b, 1, 0)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_build_transposed_get_every_other_byte(self):
        b = b'Hey there'
        expected_bytes = b'e hr'

        actual_bytes = build_transposed(b, 2, 1)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_build_transposed_n_is_larger_than_m_uses_n_mod_m(self):
        b = b'Hey there'
        expected_bytes = b'e hr'

        actual_bytes = build_transposed(b, 2, 3)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_build_transposed_n_is_negative_uses_n_mod_m(self):
        b = b'Hey there'
        expected_bytes = b'e hr'

        actual_bytes = build_transposed(b, 2, -1)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_build_transposed_negative_m_returns_empty(self):
        b = b'Hey there'
        expected_bytes = b''

        actual_bytes = build_transposed(b, -1, 1)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_build_transposed_zero_m_returns_empty(self):
        b = b'Hey there'
        expected_bytes = b''

        actual_bytes = build_transposed(b, 0, 1)

        self.assertEqual(expected_bytes, actual_bytes)
