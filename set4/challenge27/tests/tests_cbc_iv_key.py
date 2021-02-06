import unittest

from set4.challenge27.cbc_iv_key import gen_ascii_oracle, \
    gen_encryption_method, recover_key


class TestCBCIVKey(unittest.TestCase):

    def test_validate_ascii_valid_plaintext_returns_none(self):
        plaintext = b"Hello World!"
        key = b"YELLOW SUBMARINE"
        encrypt = gen_encryption_method(key)
        validate_ascii = gen_ascii_oracle(key)

        ciphertext = encrypt(plaintext)
        self.assertIsNone(validate_ascii(ciphertext))

    def test_validate_ascii_invalid_plaintext_returns_decryption(self):
        plaintext = b"This is an extended ascii character: \x80"
        key = b"YELLOW SUBMARINE"
        encrypt = gen_encryption_method(key)
        validate_ascii = gen_ascii_oracle(key)

        ciphertext = encrypt(plaintext)
        self.assertEqual(plaintext, validate_ascii(ciphertext))

    def test_recover_key_ciphertext_less_than_three_blocks_returns_none(self):
        ciphertext = b"Less than three blocks"
        key = b"YELLOW SUBMARINE"
        validate_ascii = gen_ascii_oracle(key)

        self.assertIsNone(recover_key(ciphertext, validate_ascii))

    def test_recover_key_nominal_case(self):
        plaintext = (b"The most merciful thing in the world, I think, is the "
                     b"inability of the human mind to correlate all its "
                     b"contents. We live on a placid island of ignorance in "
                     b"the midst of black seas of infinity, and it was not "
                     b"meant that we should voyage far.")
        key = b"THECALLOFCTHULHU"
        encrypt = gen_encryption_method(key)
        validate_ascii = gen_ascii_oracle(key)

        ciphertext = encrypt(plaintext)

        self.assertEqual(key, recover_key(ciphertext, validate_ascii))
