import unittest

from set1.challenge3.single_xor import *


class TestSingleXOR(unittest.TestCase):

    def test_single_xor_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            single_xor(None, b'A')

    def test_single_xor_empty_input_returns_empty_bytes(self):
        self.assertEqual(single_xor(b'', b'A'), b'')

    def test_single_xor_none_s_returns_unchanged_bytes(self):
        b = b'Hey'
        expected_bytes = b'Hey'

        actual_bytes = single_xor(b, None)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_single_xor_empty_s_returns_unchanged_bytes(self):
        b = b'Hey'
        expected_bytes = b'Hey'

        actual_bytes = single_xor(b, b'')

        self.assertEqual(expected_bytes, actual_bytes)

    def test_single_xor_nominal_case(self):
        b = b'Hey'
        s = b'A'
        expected_bytes = b'\x09\x24\x38'

        actual_bytes = single_xor(b, s)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_single_xor_s_more_than_one_byte_only_first_byte_is_used(self):
        b = b'Hey'
        s = b'Aloha'
        expected_bytes = b'\x09\x24\x38'

        actual_bytes = single_xor(b, s)

        self.assertEqual(expected_bytes, actual_bytes)
