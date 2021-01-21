import unittest

from set2.challenge13.cookie import *


class TestCookie(unittest.TestCase):

    def test_decode_cookie_cryptopals_case(self):
        encoded = "foo=bar&baz=qux&zap=zazzle"
        expected_decoded = {
          'foo': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_var_with_multiple_equals_ignores_extraneous(self):
        encoded = "foo=bar=tuf&baz=qux&zap=zazzle"
        expected_decoded = {
          'foo': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_var_without_equal_set_to_empty(self):
        encoded = "foo&baz=qux&zap=zazzle"
        expected_decoded = {
          'foo': '',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_equal_without_var_sets_empty_key(self):
        encoded = "=bar&baz=qux&zap=zazzle"
        expected_decoded = {
          '': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_starts_with_andpercent_ignores_first_character(self):
        encoded = "&foo=bar&baz=qux&zap=zazzle"
        expected_decoded = {
          'foo': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_ends_with_andpercent_ignores_last_character(self):
        encoded = "foo=bar&baz=qux&zap=zazzle&"
        expected_decoded = {
          'foo': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)

    def test_decode_cookie_var_appeares_multiple_times_is_set_to_last_value(self):
        encoded = "foo=bar&baz=qux&zap=zazzle&foo=tuf"
        expected_decoded = {
          'foo': 'tuf',
          'baz': 'qux',
          'zap': 'zazzle'
        }

        actual_decoded = decode_cookie(encoded)

        self.assertEqual(expected_decoded, actual_decoded)
