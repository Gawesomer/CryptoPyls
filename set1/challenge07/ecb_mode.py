from typing import Callable


def get_block_n(b: bytes, blk_size: int, n: int) -> bytes:
    """
    params:
        b
        blk_size
        n
    returns:
        `n`th block of size `blk_size` from `b`
        if size of `b` was not divisible by `blk_size` last block will be
        smaller
    """
    return b[n*blk_size:(n+1)*blk_size]


def blocks(b: bytes, blk_size: int) -> bytes:
    """
    generator method
    simply for ease of use
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
        yield get_block_n(b, blk_size, i)


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
