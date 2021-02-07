import unittest

from set4.challenge30.md4 import MD4


class TestMD4(unittest.TestCase):

    def test_md4_nominal_case(self):
        payload = b"The quick brown fox jumps over the lazy dog"
        expected = b"\x1b\xeei\xa4k\xa8\x11\x18\\\x19Gb\xab\xae\xae\x90"

        h = MD4()
        h.update(payload)
        res = h.digest()

        self.assertEqual(expected, res)
