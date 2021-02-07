import unittest

from set4.challenge28.sha1 import SHA1


class TestMD4(unittest.TestCase):

    def test_sha1_nominal_case(self):
        payload = b"The quick brown fox jumps over the lazy dog"
        expected = b"/\xd4\xe1\xc6z-(\xfc\xed\x84\x9e\xe1\xbbv\xe79\x1b\x93\xeb\x12"

        h = SHA1()
        h.update(payload)
        res = h.digest()

        self.assertEqual(expected, res)
