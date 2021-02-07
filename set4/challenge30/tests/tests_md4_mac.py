import unittest

from set4.challenge30.md4_mac import authenticate_message, is_valid_message


class TestMD4MAC(unittest.TestCase):

    def test_authenticate_message_is_valid_message_integration(self):
        plaintext = b"You turn yourself around. That's what it's all about."
        key = b"Hokey Pokey"
        authenticated = authenticate_message(plaintext, key)

        self.assertTrue(is_valid_message(authenticated, key))

    def test_is_valid_message_invalid_message_returns_false(self):
        plaintext = b"You turn yourself around. That's what it's all about."
        key = b"Hokey Pokey"
        authenticated = authenticate_message(plaintext, key)
        wrong_key = b"Oh no this is the wrong key"

        self.assertFalse(is_valid_message(authenticated, wrong_key))

    def test_is_valid_message_message_less_than_16_bytes_returns_false(self):
        self.assertFalse(is_valid_message(bytes(15), b''))
