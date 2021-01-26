from __future__ import annotations
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


class BlockCipherMode():

    def __init__(
            self: BlockCipherMode,
            blksize: int,
            encrypt_blk: Callable[[bytes], bytes],
            decrypt_blk: Callable[[bytes], bytes]) \
            -> BlockCipherMode:
        """
        params:
            blksize: positive integer
            encrypt_blk: block cipher encryption transform operating on blocks
                         of size `blksize`
            decrypt_blk: inverse of `encrypt`
        raises:
            ValueError: if `blksize` is invalid
        """
        if blksize <= 0:
            raise ValueError("Invalid blksize: %s" % blksize)

        self.blksize = blksize
        self.encrypt_blk = encrypt_blk
        self.decrypt_blk = decrypt_blk

    def encrypt(self, plaintext: bytes):
        """
        params:
            plaintext: bytes to encrypt
                       should be padded to have size divisible by
                       `self.blksize`
        returns:
            `plaintext` encrypted
        """
        raise(NotImplementedError)

    def decrypt(self, ciphertext: bytes):
        """
        params:
            ciphertext: bytes to decrypt
                        should be padded to have size divisible by
                        `self.blksize`
        returns:
            `ciphertext` decrypted
        """
        raise(NotImplementedError)


class ECBMode(BlockCipherMode):
    """
    Applies the cipher to each block individually
    """

    def encrypt(self, plaintext: bytes):
        """
        raises:
            ValueError: if size of `plaintext` is not divisible by
                        `self.blksize`
        """
        if len(plaintext) % self.blksize != 0:
            raise ValueError("plaintext is not %s-bit padded" % self.blksize)

        ciphertext = b''

        for block in blocks(plaintext, self.blksize):
            ciphertext += self.encrypt_blk(block)

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        raises:
            ValueError: if size of `ciphertext` is not divisible by
                        `self.blksize`
        """
        if len(ciphertext) % self.blksize != 0:
            raise ValueError("ciphertext is not %s-bit padded" % self.blksize)

        plaintext = b''

        for block in blocks(ciphertext, self.blksize):
            plaintext += self.decrypt_blk(block)

        return plaintext
