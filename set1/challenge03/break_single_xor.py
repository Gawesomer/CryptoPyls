import sys

from set1.challenge3.single_xor import single_xor


"""
English letter frequency based on a sample of 40,000 words obtained from:
http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
Also contains a frequency for the space character
"""
ENGLISH_LETTER_FREQ = {
        'a': 8.12,
        'b': 1.49,
        'c': 2.71,
        'd': 4.32,
        'e': 12.02,
        'f': 2.30,
        'g': 2.03,
        'h': 5.92,
        'i': 7.31,
        'j': 0.10,
        'k': 0.69,
        'l': 3.98,
        'm': 2.61,
        'n': 6.95,
        'o': 7.68,
        'p': 1.82,
        'q': 0.11,
        'r': 6.02,
        's': 6.28,
        't': 9.10,
        'u': 2.88,
        'v': 1.11,
        'w': 2.09,
        'x': 0.17,
        'y': 2.11,
        'z': 0.07,
        ' ': 18.00,
}


def freq_score(b: bytes, freq: dict = ENGLISH_LETTER_FREQ) -> float:
    """
    params:
        b: bytes to analyze
        freq: letter to float dictionary representing frequency of common
              letters is an alphabet
    returns:
        score of `b`
        a higher frequency score indicates a closer resemblence to the
        language described by `freq`
    """
    if not b:
        return 0

    score = 0
    for c in b.decode("utf-8", errors="ignore").lower():
        score += freq.get(c, 0)
    return score


def break_single_xor(encrypted: bytes) -> list:
    """
    params:
        encrypted: bytes encrypted using single-xor
    returns:
        list of dict {'message': bytes, 'key': bytes: 'score': float}
        sorted in descending order by score
    """
    res = list()
    for i in range(0, 256):
        b = i.to_bytes(1, byteorder=sys.byteorder)
        xored = single_xor(encrypted, b)
        score = freq_score(xored)
        res.append({'message': xored, 'key': b, 'score': score})
    res.sort(key=lambda d: d['score'], reverse=True)
    return res
