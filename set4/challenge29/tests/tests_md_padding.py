import unittest

from set2.challenge09.pkcs7_padding import InvalidPaddingException
from set4.challenge29.md_padding import MDPadding


class TestMDPadding(unittest.TestCase):

    def test_apply_multiple_padding_bytes(self):
        plaintext = b"This message is exactly fourty seven bytes long"
        expected_padded = plaintext + b'\x80' + bytes(8) + \
            b"\x00\x00\x00\x00\x00\x00\x01\x78"

        actual_padded = MDPadding.apply(plaintext)

        self.assertEqual(expected_padded, actual_padded)

    def test_apply_single_padding_byte(self):
        plaintext = b"This message has fifty five characters in it some more."
        expected_padded = plaintext + b'\x80' + \
            b"\x00\x00\x00\x00\x00\x00\x01\xb8"

        actual_padded = MDPadding.apply(plaintext)

        self.assertEqual(expected_padded, actual_padded)

    def test_apply_messagesize_56_mod_64_append_whole_block_of_padding(self):
        plaintext = b"Hello this string is fifty six bytes here are some more."
        expected_padded = plaintext + b'\x80' + bytes(63) + \
            b"\x00\x00\x00\x00\x00\x00\x01\xc0"

        actual_padded = MDPadding.apply(plaintext)

        self.assertEqual(expected_padded, actual_padded)

    def test_apply_multiple_blocks(self):
        plaintext = bytes(128) + \
            b"This message is exactly fourty seven bytes long"
        expected_padded = plaintext + b'\x80' + bytes(8) + \
            b"\x00\x00\x00\x00\x00\x00\x05x"

        actual_padded = MDPadding.apply(plaintext)

        self.assertEqual(expected_padded, actual_padded)

    def test_unapply_multiple_padding_bytes(self):
        expected = b"This message is exactly fourty seven bytes long"
        padded = expected + b'\x80' + bytes(8) + \
            b"\x00\x00\x00\x00\x00\x00\x01\x78"

        actual = MDPadding.unapply(padded)

        self.assertEqual(expected, actual)

    def test_unapply_single_padding_byte(self):
        expected = b"This message has fifty five characters in it some more."
        padded = expected + b'\x80' + \
            b"\x00\x00\x00\x00\x00\x00\x01\xb8"

        actual = MDPadding.unapply(padded)

        self.assertEqual(expected, actual)

    def test_unapply_messagesize_56_mod_64_whole_block_of_padding(self):
        expected = b"Hello this string is fifty six bytes here are some more."
        padded = expected + b'\x80' + bytes(55) + \
            b"\x00\x00\x00\x00\x00\x00\x01\xc0"

        actual = MDPadding.unapply(padded)

        self.assertEqual(expected, actual)

    def test_unapply_multiple_blocks(self):
        expected = bytes(128) + \
            b"This message is exactly fourty seven bytes long"
        padded = expected + b'\x80' + bytes(8) + \
            b"\x00\x00\x00\x00\x00\x00\x05x"

        actual = MDPadding.unapply(padded)

        self.assertEqual(expected, actual)

    def test_unapply_length_does_not_match(self):
        expected = b"This message is exactly fourty seven bytes long"
        padded = expected + b'\x80' + bytes(8) + \
            b"\x00\x00\x00\x00\x00\x00\x01\x70"
        with self.assertRaises(InvalidPaddingException):
            MDPadding.unapply(padded)
