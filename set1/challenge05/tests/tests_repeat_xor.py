import unittest

from set1.challenge05.repeat_xor import repeat_xor


class TestRepeatXOR(unittest.TestCase):

    def test_repeat_xor_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            repeat_xor(None, b'A')

    def test_repeat_xor_empty_input_returns_empty_bytes(self):
        self.assertEqual(repeat_xor(b'', b'A'), b'')

    def test_repeat_xor_none_key_returns_unchanged_bytes(self):
        b = b'Hey'
        expected_bytes = b'Hey'

        actual_bytes = repeat_xor(b, None)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_repeat_xor_empty_key_returns_unchanged_bytes(self):
        b = b'Hey'
        expected_bytes = b'Hey'

        actual_bytes = repeat_xor(b, b'')

        self.assertEqual(expected_bytes, actual_bytes)

    def test_repeat_xor_single_byte_key(self):
        b = b'Hey'
        key = b'A'
        expected_bytes = b'\x09\x24\x38'

        actual_bytes = repeat_xor(b, key)

        self.assertEqual(expected_bytes, actual_bytes)

    def test_repeat_xor_cryptopals_case(self):
        b = (b"Burning 'em, if you ain't quick and nimble\n"
             b"I go crazy when I hear a cymbal")
        key = b"ICE"
        expected_hex = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d633"
                        "43c2a26226324272765272"
                        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028"
                        "3165286326302e27282f")

        actual_bytes = repeat_xor(b, key)
        actual_hex = actual_bytes.hex()

        self.assertEqual(expected_hex, actual_hex)
