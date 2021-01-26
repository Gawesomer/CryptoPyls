from __future__ import annotations
from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import blocks, BlockCipherMode


class CBCMode(BlockCipherMode):

    def encrypt(self: CBCMode, plaintext: bytes) -> bytes:
        """
        XORs each block with the cipher of the previous block (or the IV if
        first block), then encrypts
        raises:
            ValueError: if size of `plaintext` is not divisible by
                        `self.blksize`
        """
        if len(plaintext) % self.blksize != 0:
            raise ValueError("plaintext is not %s-bit padded" % self.blksize)

        ciphertext = b''

        prev_cipherblk = self.iv
        for block in blocks(plaintext, self.blksize):
            prev_cipherblk = self.encrypt_blk(xor(block, prev_cipherblk))
            ciphertext += prev_cipherblk

        return ciphertext

    def decrypt(self: CBCMode, ciphertext: bytes) -> bytes:
        """
        decrypts each block, then XORs with cipher of the previous block
        (or IV if first block)
        raises:
            ValueError: if size of `plaintext` is not divisible by
                        `self.blksize`
        """
        if len(ciphertext) % self.blksize != 0:
            raise ValueError("ciphertext is not %s-bit padded" % self.blksize)

        plaintext = b''

        prev_cipherblk = self.iv
        for block in blocks(ciphertext, self.blksize):
            plaintext += xor(self.decrypt_blk(block), prev_cipherblk)
            prev_cipherblk = block

        return plaintext
