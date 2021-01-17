import sys

from set1.challenge2.fixed_xor import xor


def repeat_xor(b: bytes, key: bytes) -> bytes:
    """
    params:
        b: bytes to be XORed
        key: key used for encryption
    returns:
        result of XORing bytes of `b` with bytes of `key` by cycling through
        the `key`
    """
    if not key:
        return b

    operand = b''
    j = 0
    key_len = len(key)
    for i in range(len(b)):
        operand += key[j].to_bytes(1, byteorder=sys.byteorder)
        j = (j+1) % key_len
    return xor(b, operand)
