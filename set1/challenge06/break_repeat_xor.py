import base64
from itertools import combinations
import os
import pathlib
import sys

from set1.challenge03.break_single_xor import break_single_xor
from set1.challenge05.repeat_xor import repeat_xor


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
        if (b1 & 1) != (b2 & 1):
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


def normalized_blk_hamming_avg(b: bytes, blk_size: int, num_blks) -> float:
    """
    params:
        b
        blk_size
        num_blks
    returns:
        normalized hamming distance between `num_blks` blocks of
        size `blk_size` within `b`
        None if `b` is two small to be broken down into at least two blocks
    """
    score = 0
    blocks = [b[i*blk_size:(i+1)*blk_size] for i in range(num_blks)]
    blocks = [b for b in blocks if b != b'']    # filter out empty blocks
    if len(blocks) < 2:
        return None
    num_combinations = 0
    for blk1, blk2 in combinations(blocks, 2):
        score += hamming_dist(blk1, blk2)
        num_combinations += 1
    score /= (num_combinations*blk_size)
    return score


def find_keysize(encrypted: bytes, num_blks: int = 4, max_keysize: int = 40) \
        -> list:
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
        score = normalized_blk_hamming_avg(encrypted, keysize, num_blks)
        if not score:
            break
        res.append({'keysize': keysize, 'score': score})

    res.sort(key=lambda d: d['score'])
    return [d['keysize'] for d in res]


def build_transposed(b: bytes, m: int, n: int) -> bytes:
    """
    params:
        b
        m
        n
    returns:
        bytes containing every `n`th byte of `b` mod `m`
    """
    res = b''
    if m <= 0:
        return res

    i = n % m
    while i < len(b):
        res += b[i].to_bytes(1, byteorder=sys.byteorder)
        i += m
    return res


def break_repeat_xor(encrypted: bytes, keysize: int) -> list:
    """
    params:
        encrypted: bytes encrypted using repeat-xor
    returns:
        dictionary {'message': bytes, 'key': bytes} with most likely
        decrypted message and key using given `keysize`
    """
    key = b''
    for i in range(keysize):
        key += break_single_xor(
            build_transposed(encrypted, keysize, i)
        )[0]['key']
    return {'message': repeat_xor(encrypted, key), 'key': key}


if __name__ == "__main__":
    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, 'r') as input_file:
        base64_str = input_file.read()
    base64_bytes = base64_str.replace('\n', '').encode("utf-8")
    encrypted = base64.decodebytes(base64_bytes)

    keysize = find_keysize(encrypted)[0]

    for k, v in break_repeat_xor(encrypted, keysize).items():
        print("%s: %s" % (k, v))
