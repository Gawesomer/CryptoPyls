from typing import Callable
import sys


def blocks(b: bytes, blk_size: int) -> bytes:
    """
    params:
        b: should be padded to have size divisible by `blk_size`
        blk_size: positive integer
    returns:
        nth block of size `blk_size` from `b`
        if size of `b` was not divisible by `blk_size` last block is ignored
    """
    if blk_size <= 0:
        return b''

    num_blcks = (len(b)//blk_size)
    for i in range(num_blcks):
        curr = b''
        yield b[i*blk_size:(i+1)*blk_size]


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

    for block in blocks(b, blk_size):
        res += fun(block)

    return res
