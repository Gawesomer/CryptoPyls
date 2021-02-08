import unittest

from set4.challenge28.mac import MAC
from set4.challenge28.sha1 import SHA1
from set4.challenge29.break_sha1_mac import length_extension


class TestBreakSHA1MAC(unittest.TestCase):

    def test_length_extension_nominal_case(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = MAC.generate(plaintext, key, SHA1)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: MAC.validate(msg, key, SHA1)
        )

        self.assertTrue(newmessage.endswith(newtext))
        self.assertTrue(MAC.validate(newmessage, key, SHA1))

    def test_length_extension_keysize_not_found_returns_none(self):
        key = b"I'm gettin' rid of Britta"
        plaintext = b"I'm gettin' rid of the B"
        message = MAC.generate(plaintext, key, SHA1)
        newtext = b"She's a no good B"

        newmessage = length_extension(
            message,
            newtext,
            lambda msg: MAC.validate(msg, key, SHA1),
            5
        )

        self.assertIsNone(newmessage)
