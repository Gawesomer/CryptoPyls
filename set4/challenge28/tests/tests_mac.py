import unittest

from set4.challenge28.mac import MAC
from set4.challenge28.sha1 import SHA1


class TestMAC(unittest.TestCase):

    def test_generate_validate_integration(self):
        plaintext = b"You turn yourself around. That's what it's all about."
        key = b"Hokey Pokey"
        authenticated = MAC.generate(plaintext, key, SHA1)

        self.assertTrue(MAC.validate(authenticated, key, SHA1))

    def test_validate_invalid_message_returns_false(self):
        plaintext = b"You turn yourself around. That's what it's all about."
        key = b"Hokey Pokey"
        authenticated = MAC.generate(plaintext, key, SHA1)
        wrong_key = b"Oh no this is the wrong key"

        self.assertFalse(MAC.validate(authenticated, wrong_key, SHA1))

    def test_validate_message_less_than_20_bytes_returns_false(self):
        self.assertFalse(MAC.validate(bytes(19), b'', SHA1))
