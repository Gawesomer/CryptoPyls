import unittest

from set4.challenge28.mac import MAC
from set4.challenge30.md4 import MD4
from set4.challenge30.break_md4_mac import length_extension


class TestBreakMD4MAC(unittest.TestCase):

    def test_length_extension_nominal_case(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = MAC.generate(plaintext, key, MD4)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: MAC.validate(msg, key, MD4)
        )

        self.assertTrue(newmessage.endswith(newtext))
        self.assertTrue(MAC.validate(newmessage, key, MD4))

    def test_length_extension_keysize_not_found_returns_none(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = MAC.generate(plaintext, key, MD4)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: MAC.validate(msg, key, MD4),
            5
        )

        self.assertIsNone(newmessage)
