from __future__ import annotations
from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import get_block_n, BlockCipherMode


class CTRMode(BlockCipherMode):

    def __init__(
            self: CTRMode,
            nonce: bytes,
            counter: Callable[[], int] = None,
            combine: Callable[[bytes, int, int], bytes] = None,
            **kwargs: dict) \
            -> CTRMode:
        """
        params:
            nonce: used to initialize CTRMode
            counter: method that generates a sequence guaranteed not to repeat
                     for a long time
            combine: method used to combine `nonce` with result of `counter`
        """
        super().__init__(**kwargs)

        self.nonce = nonce

        if counter is None:
            self.counter = CTRMode.default_counter
        else:
            self.counter = counter

        if combine is None:
            self.combine = CTRMode.default_combine
        else:
            self.combine = combine

    @classmethod
    def default_counter(cls: CTRMode) -> bytes:
        """
        params:
            none
        returns:
            sequence of natural numbers
        """
        i = 0
        while True:
            yield i
            i += 1

    @classmethod
    def default_combine(
            cls: CTRMode,
            nonce: bytes,
            blk_count: int,
            blksize: int) \
            -> bytes:
        """
        params:
            nonce: `nonce` being used by CTRMode
            blk_count: current block count generated from `counter`
            blksize: positive integer
        returns:
            concatenation of 64 bit unsigned little endian `nonce` with
            64 bit little endian `blck_count`
            if `nonce` is less than 64 bits, it will be padded with '\x00's
            if either is more than 64 bits, extraneous bits will be discarded
        raises:
            OverflowError: if `blk_count` too large
        """
        if blksize <= 0:
            raise ValueError("Invalid blksize: %s" % blksize)

        half_blksize = blksize//2
        nonce_size = len(nonce)
        if nonce_size < half_blksize:
            nonce += bytes(half_blksize-nonce_size)

        return nonce[:half_blksize] + blk_count.to_bytes(8, byteorder="little")

    def encrypt(self: CBCMode, plaintext: bytes) -> bytes:
        """
        Use cipher to encrypt combination of nonce and block counter,
        then XORs the result with the block
        """
        ciphertext = b''

        i = 0
        for blk_count in self.counter():
            curr_blk = get_block_n(plaintext, self.blksize, i)
            if curr_blk == b'':
                break
            counter_blk = self.combine(self.nonce, blk_count, self.blksize)
            ciphertext += xor(curr_blk, self.encrypt_blk(counter_blk))
            i += 1

        return ciphertext

    def decrypt(self: CBCMode, ciphertext: bytes) -> bytes:
        """
        Use cipher to encrypt combination of nonce and block counter,
        then XORs the result with the block
        """
        return self.encrypt(ciphertext)
