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

    def test_normalized_blk_hamming_avg_none_bytes_raises_typeerror(self):
        with self.assertRaises(TypeError):
            normalized_blk_hamming_avg(None, 1, 1)

    def test_normalized_blk_hamming_avg_invalid_blk_variables_return_none(self):
        b = b'Hey there'

        self.assertIsNone(normalized_blk_hamming_avg(b, -1, 1))
        self.assertIsNone(normalized_blk_hamming_avg(b, 1, -1))

    def test_normalized_blk_hamming_avg_identical_blocks_returns_zero(self):
        b = b'HeyHeyHey'
        expected_score = 0

        actual_score = normalized_blk_hamming_avg(b, 3, 3)

        self.assertEqual(expected_score, actual_score)

    def test_normalized_blk_hamming_avg_nominal_case(self):
        b = b'this is a testwokka wokka!!!'
        expected_score = 37/14

        actual_score = normalized_blk_hamming_avg(b, 14, 2)

        self.assertEqual(expected_score, actual_score)

    def test_normalized_blk_hamming_avg_bytes_too_short_returns_none(self):
        b = b'Hey there'

        self.assertIsNone(normalized_blk_hamming_avg(b, 16, 4))

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
        encrypted = base64.decodebytes(base64_bytes)
        expected_keysize = 29

        actual_keysizes = find_keysize(encrypted)

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

    def test_break_repeat_xor_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            break_repeat_xor(None, 1)

    def test_break_repeat_xor_empty_input_returns_empty_message(self):
        expected_message = b''

        actual_res = break_repeat_xor(b'', 1)

        self.assertEqual(expected_message, actual_res['message'])

    def test_break_repeat_xor_invalid_keysize_returns_message_unchanged(self):
        encrypted = b'Hey there'
        expected_message = b'Hey there'
        expected_key = b''

        actual_res = break_repeat_xor(encrypted, -1)

        self.assertEqual(expected_message, actual_res['message'])
        self.assertEqual(expected_key, actual_res['key'])

    def test_break_repeat_xor_cryptopals_case(self):
        input_filename = os.path.join(
            pathlib.Path(__file__).parent.parent,
            "input"
        )
        with open(input_filename, 'r') as input_file:
            base64_str = input_file.read()
        base64_bytes = base64_str.replace('\n', '').encode("utf-8")
        encrypted = base64.decodebytes(base64_bytes)
        keysize = 29
        expected_key = b'Terminator X: Bring the noise'

        actual_res = break_repeat_xor(encrypted, keysize)

        self.assertEqual(expected_key, actual_res['key'])
