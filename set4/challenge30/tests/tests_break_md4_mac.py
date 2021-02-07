import unittest

from set4.challenge30.md4_mac import authenticate_message, is_valid_message
from set4.challenge30.break_md4_mac import length_extension


class TestBreakMD4MAC(unittest.TestCase):

    def test_length_extension_nominal_case(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = authenticate_message(plaintext, key)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: is_valid_message(msg, key)
        )

        self.assertTrue(newmessage.endswith(newtext))
        self.assertTrue(is_valid_message(newmessage, key))

    def test_length_extension_keysize_not_found_returns_none(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = authenticate_message(plaintext, key)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: is_valid_message(msg, key),
            5
        )

        self.assertIsNone(newmessage)
