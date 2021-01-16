import sys


def xor(b1: bytes, b2: bytes) -> bytes:
    """
    params:
        b1
        b2
    returns:
        XOR combination of `b1` and `b2`
        if `b1` and `b2` are not the same size, returned XOR combination is the
        size of the smaller of the two
    raises:
        TypeError if input is None
    """
    res = b''
    min_len = min(len(b1), len(b2))
    for i in range(min_len):
        res += (b1[i]^b2[i]).to_bytes(1, byteorder=sys.byteorder)
    return res
