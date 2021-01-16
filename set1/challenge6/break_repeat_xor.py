from itertools import combinations


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


def find_keysize(encrypted: bytes, num_blks: int = 4, max_keysize: int = 40) -> list:
    """
    params:
        encrypted: bytes encrypted using repeat-xor
        num_blks: number of blocks to use to determine likeliness of keysize
                  more blocks yields greater accuracy
        max_keysize: maximum keysize that should be tested for
    returns:
        list of integer keysizes sorted in decreasing order of likeliness
    """
    res = list()
    if num_blks <= 0:
        return res

    for keysize in range(2, max_keysize+1):
        score = 0
        blocks = [encrypted[i*keysize:(i+1)*keysize] for i in range(num_blks)]
        blocks = [b for b in blocks if b != b'']    # filter out empty blocks
        if len(blocks) < 2:
            break
        num_combinations = 0
        for blk1, blk2 in combinations(blocks, 2):
            score += hamming_dist(blk1, blk2)
            num_combinations += 1
        score /= (num_combinations*keysize)
        res.append({'keysize': keysize, 'score': score})

    res.sort(key=lambda d: d['score'])
    return [d['keysize'] for d in res]
