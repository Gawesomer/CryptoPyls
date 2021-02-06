import unittest

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
        expected_padded = plaintext + b'\x80' + bytes(55) + \
            b"\x00\x00\x00\x00\x00\x00\x01\xc0"

        actual_padded = MDPadding.apply(plaintext)

        self.assertEqual(expected_padded, actual_padded)
