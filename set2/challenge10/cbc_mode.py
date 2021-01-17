from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import blocks


def cbc_mode(b: bytes, blk_size: int, iv: bytes, fun: Callable[[bytes], bytes]) \
        -> bytes:
    """
    params:
        b: should be padded to have size divisible by `blk_size`
        blk_size: positive integer
        iv: should be of size `blk_size` if larger extraneous bytes are ignored
        fun: function to apply on each block
    returns:
        concatenation of results of applying `fun` on each block of `b`
        whilst XORing result of previous block with next block
        if size of `b` was not divisible by `blk_size` last block is ignored
    """
    res = b''
    if len(iv) < blk_size:
        return res

    for block in blocks(b, blk_size):
        iv = fun(xor(block, iv))
        res += iv

    return res
