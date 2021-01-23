from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import blocks


def cbc_mode_encrypt(b: bytes, blksize: int, iv: bytes, fun: Callable[[bytes], bytes]) \
        -> bytes:
    """
    params:
        b: should be padded to have size divisible by `blksize`
        blksize: positive integer
        iv: should be of size `blksize` if larger extraneous bytes are ignored
        fun: function to apply on each block
    returns:
        concatenation of results of applying `fun` on each block of `b`
        whilst XORing result of previous block with next block
        if size of `b` was not divisible by `blksize` last block is ignored
    """
    res = b''
    if len(iv) < blksize:
        return res

    for block in blocks(b, blksize):
        iv = fun(xor(block, iv))
        res += iv

    return res


def cbc_mode_decrypt(b: bytes, blksize: int, iv: bytes, fun: Callable[[bytes], bytes]) \
        -> bytes:
    """
    params:
        b: should be padded to have size divisible by `blksize`
        blksize: positive integer
        iv: should be of size `blksize` if larger extraneous bytes are ignored
        fun: function to apply on each block
    returns:
        concatenation of results of applying `fun` on each block of `b`
        whilst XORing result of previous block with next block
        if size of `b` was not divisible by `blksize` last block is ignored
    """
    res = b''

    for block in blocks(b, blksize):
        res += xor(fun(block), iv)
        iv = block

    return res
