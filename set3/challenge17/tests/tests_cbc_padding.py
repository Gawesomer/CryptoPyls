import unittest

from set3.challenge17.cbc_padding import *


class TestCBCPadding(unittest.TestCase):

    def test_valid_padding_integration_padding_is_valid(self):
        encrypted, iv = encryption_oracle()

        self.assertTrue(valid_padding(encrypted, iv))

    def test_valid_padding_padding_is_invalid(self):
        encrypted, iv = encryption_oracle()
        encrypted = encrypted[:-1] + b'\x00'

        self.assertFalse(valid_padding(encrypted, iv))
