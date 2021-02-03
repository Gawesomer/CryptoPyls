from __future__ import annotations
from typing import Callable

from set3.challenge21.mersenne_rng import MT19937


class MT19937Cipher:
    """
    Stream cipher that uses all four bytes in little-endian order from each
    pseudo-random number generated from a MT19937 as its keystream
    """

    def __init__(
            self: MT19937Cipher,
            seed: int,
            gen_key: Callable[[MT19937], bytes] = None) \
            -> MT19937Cipher:
        """
        params:
            seed: seed for MT19937
            gen_key: generator method to generate key stream from results
                     of MT19937
        """
        if gen_key is None:
            gen_key = self.default_gen_key
        self.gen_key = gen_key

        self.seed = seed

    @classmethod
    def default_gen_key(cls: MT19937Cipher, mt: MT19937) -> int:
        """
        params:
            mt: seeded MT19937
        returns:
            sequence of ints to be used as keystream
        """
        generated = list(mt.extract_number().to_bytes(4, byteorder="little"))
        byte_index = -1
        while True:
            byte_index += 1
            if byte_index >= 4:
                generated = list(
                    mt.extract_number().to_bytes(4, byteorder="little")
                )
                byte_index = 0
            yield generated[byte_index]

    def encrypt(self: MT19937Cipher, plaintext: bytes) -> bytes:
        """
        params:
            plaintext: bytes to encrypt
        returns:
            `plaintext` XORed with keystream generated by `gen_key`
        """
        mt = MT19937()
        mt.seed_mt(self.seed)
        ciphertext = b''

        for plain, key in zip(plaintext, self.gen_key(mt)):
            ciphertext += (plain ^ key).to_bytes(1, byteorder="little")

        return ciphertext

    def decrypt(self: MT19937Cipher, ciphertext: bytes) -> bytes:
        """
        params:
            ciphertext: bytes to be decrypted
        returns:
            decryption of `ciphertext`
        """
        return self.encrypt(ciphertext)