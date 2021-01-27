import unittest

from set2.challenge16.cbc_bitflip import gen_encryption_oracle, is_admin


class TestCBCBitflip(unittest.TestCase):

    def test_encryption_oracle_is_admin_integration_is_admin_false(self):
        encryption_oracle = gen_encryption_oracle()

        encrypted = encryption_oracle(b'')

        self.assertFalse(is_admin(encrypted))

    def test_encryption_oracle_is_admin_integration_is_admin_true(self):
        prefix = b"comment1=cooking%20MCs;userdata="
        suffix = b"hello;admin=true;comment2=%20like%20a%20pound%20of%20bacon"
        encryption_oracle = gen_encryption_oracle(prefix=prefix, suffix=suffix)

        encrypted = encryption_oracle(b'')

        self.assertTrue(is_admin(encrypted))

    def test_encryption_oracle_is_admin_integration_admin_string_cant_be_inputed(self):
        encryption_oracle = gen_encryption_oracle()

        encrypted = encryption_oracle(b";admin=true;")

        self.assertFalse(is_admin(encrypted))
