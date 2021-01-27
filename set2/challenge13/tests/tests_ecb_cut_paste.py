import unittest

from set2.challenge13.ecb_cut_paste import decrypt_profile, encrypt_profile, \
    profile_for


class TestECBCutPaste(unittest.TestCase):

    def test_profile_for_cryptopals_case(self):
        expected_encoded = "email=foo@bar.com&uid=10&role=user"

        actual_encoded = profile_for("foo@bar.com")

        self.assertEqual(expected_encoded, actual_encoded)

    def test_profile_for_invalid_characters_are_removed(self):
        expected_encoded = "email=foo@bar.comroleadmin&uid=10&role=user"

        actual_encoded = profile_for("foo@bar.com&role=admin")

        self.assertEqual(expected_encoded, actual_encoded)

    def test_encrypt_decrypt_profile_integration(self):
        encoded_profile = "email=foo@bar.com&uid=10&role=user"

        encrypted = encrypt_profile(encoded_profile)
        decrypted = decrypt_profile(encrypted)

        self.assertEqual(encoded_profile, decrypted)
