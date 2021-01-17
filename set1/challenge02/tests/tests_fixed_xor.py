import unittest

from set1.challenge02.fixed_xor import *


class TestFixedXOR(unittest.TestCase):

    def test_xor_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            xor(None, None)

    def test_xor_empty_input_returns_empty_bytes(self):
        self.assertEqual(xor(b'', b''), b'')

    def test_xor_bytes_of_different_length_only_xors_up_to_smallest_length(self):
        bytes1 = b'\xD4\x1D\x28'
        bytes2 = b'\x9C\x78\x51'
        expected_bytes = b'Hey'

        actual_bytes = xor(bytes1, bytes2)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_xor_cryptopals_case(self):
        hex1 = '1c0111001f010100061a024b53535009181c'
        bytes1 = bytes.fromhex(hex1)
        hex2 = '686974207468652062756c6c277320657965'
        bytes2 = bytes.fromhex(hex2)
        expected_hex = '746865206b696420646f6e277420706c6179'
        expected_bytes = bytes.fromhex(expected_hex)

        actual_bytes = xor(bytes1, bytes2)

        self.assertEqual(expected_bytes, actual_bytes)
