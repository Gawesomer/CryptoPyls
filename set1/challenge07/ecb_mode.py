from typing import Callable
import sys


def ecb_mode(b: bytes, blk_size: int, fun: Callable[[bytes], bytes]) -> bytes:
    """
    params:
        b: should be padded to have size divisible by `blk_size`
        blk_size: positive integer
        fun: function to apply on each block
    returns:
        concatenation of results of applying `fun` on each block of `b`
        if size of `b` was not divisible by `blk_size` last block is ignored
    """
    res = b''
    if blk_size <= 0:
        return res

    num_blcks = (len(b)//blk_size)
    for i in range(num_blcks):
        curr = b''
        for j in range(blk_size):
            curr += b[(i*blk_size)+j].to_bytes(1, byteorder=sys.byteorder)
        res += fun(curr)
    return res
