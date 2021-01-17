import unittest

from set1.challenge3.break_single_xor import *


class TestFreqScore(unittest.TestCase):

    def test_freq_score_none_input_returns_zero(self):
        self.assertEqual(freq_score(None), 0)

    def test_freq_score_empty_input_returns_zero(self):
        self.assertEqual(freq_score(b''), 0)

    def test_freq_score_nominal_case(self):
        b = b'Hey there'
        expected_score = 2*ENGLISH_LETTER_FREQ['h'] + \
            3*ENGLISH_LETTER_FREQ['e'] + ENGLISH_LETTER_FREQ['y'] + \
            ENGLISH_LETTER_FREQ[' '] + ENGLISH_LETTER_FREQ['t'] + \
            ENGLISH_LETTER_FREQ['r']

        actual_score = freq_score(b)

        self.assertEqual(expected_score, actual_score)


class TestBreakSingleXOR(unittest.TestCase):

    def test_break_single_xor_none_input_raises_typeerror(self):
        with self.assertRaises(TypeError):
            break_single_xor(None)

    def test_break_single_xor_cryptopals_case(self):
        hexstr = ('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783'
                  'a393b3736')
        b = bytes.fromhex(hexstr)
        expected_message = b"Cooking MC's like a pound of bacon"
        expected_key = b'X'

        actual = break_single_xor(b)

        self.assertEqual(expected_message, actual[0]['message'])
        self.assertEqual(expected_key, actual[0]['key'])
