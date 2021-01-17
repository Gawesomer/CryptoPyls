import binascii
import unittest

from set1.challenge01.encode import *


class TestEncode(unittest.TestCase):

    def test_hextob64_none_hexstr_raises_typeerror(self):
        with self.assertRaises(TypeError):
            hextob64(None)

    def test_hextob64_invalid_hexstr_raises_valueerror(self):
        with self.assertRaises(ValueError):
            hextob64('a')

    def test_hextob64_cryptopals_case(self):
        hexstr = ('49276d206b696c6c696e6720796f757220627261696e206c696b6520612'
                  '0706f69736f6e6f7573206d757368726f6f6d')
        expected_b64 = (b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3Vz'
                        b'IG11c2hyb29t')

        actual_b64 = hextob64(hexstr)

        self.assertEqual(expected_b64, actual_b64)

    def test_b64tohex_none_b64bytes_raises_typeerror(self):
        with self.assertRaises(TypeError):
            b64tohex(None)

    def test_b64tohex_invalid_b64bytes_raises_binasciierror(self):
        with self.assertRaises(binascii.Error):
            b64tohex(b'a')

    def test_b64tohex_cryptopals_case(self):
        b64bytes = (b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11'
                    b'c2hyb29t')
        expected_hex = ('49276d206b696c6c696e6720796f757220627261696e206c696b6'
                        '5206120706f69736f6e6f7573206d757368726f6f6d')

        actual_hex = b64tohex(b64bytes)

        self.assertEqual(expected_hex, actual_hex)
