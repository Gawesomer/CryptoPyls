def hamming_dist_int(b1: int, b2: int) -> int:
    """
    params:
        b1
        b2
    returns:
        number of differing bits between binary representations
        of `b1` and `b2`
    """
    res = 0
    while b1 > 0 or b2 > 0:
        if (b1&1) != (b2&1):
            res += 1
        b1 = b1 >> 1
        b2 = b2 >> 1
    return res


def hamming_dist(b1: bytes, b2: bytes) -> int:
    """
    params:
        b1
        b2
    returns:
        number of differing bits between `b1` and `b2`
        if `b1` and `b2` are not the same size, hamming distance is only
        computed over the size of the smaller of the two
    """
    res = 0
    min_len = min(len(b1), len(b2))
    for i in range(min_len):
        res += hamming_dist_int(b1[i], b2[i])
    return res
