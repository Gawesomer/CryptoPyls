import sys

from set1.challenge2.fixed_xor import xor


def single_xor(b: bytes, s: bytes) -> bytes:
    """
    params:
        b: bytes to be XORed
        s: single byte used for encryption
    returns:
        result of XORing every byte of `b` with `s`
        if `s` is more than one byte, only first byte is used
    raises:
        TypeError if `b` is None
    """
    if not s:
        return b

    operand = b''
    for i in range(len(b)):
        operand += s[0].to_bytes(1, byteorder=sys.byteorder)
    return xor(b, operand)
