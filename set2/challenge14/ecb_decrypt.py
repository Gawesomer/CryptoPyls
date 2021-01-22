import base64
from Crypto.Cipher import AES
import random
import sys
from typing import Callable, Tuple

from set1.challenge07.ecb_mode import ecb_mode, get_block_n, blocks
from set2.challenge09.pkcs7_padding import pkcs7_pad
from set2.challenge11.rand_enc import rand_bytes_gen, is_ecb


CONSISTENT_KEY = rand_bytes_gen(16)


def gen_encryption_oracle(blksize: int = 16, unknownstr: bytes = None, randbytes: bytes = None) \
        -> Callable[[bytes], bytes]:
    """
    params:
        blksize: blocksize `encryption_oracle` should use
        unknownstr: bytes that attacker should obtain
        randbytes: random number of random bytes that should be prepended to
                   the message
    returns:
        `encryption_oracle` method
    """
    if not unknownstr:
        b64bytes = (
            b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            b"YnkK"
        )
        unknownstr = base64.b64decode(b64bytes)

    if randbytes is None:
        randbytes= rand_bytes_gen(random.randint(0, 255))

    def encryption_oracle(b: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128-ECB
            appends `unknownstr` and prepends consistent random bytes to `b`
            before encrypting
        """
        plain = pkcs7_pad(randbytes+b+unknownstr, blksize)
        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)

        return ecb_mode(plain, blksize, cipher.encrypt)

    return encryption_oracle


def determine_randbytes_size(encrypt: Callable[[bytes], bytes], blksize: int) \
        -> Tuple[int, int]:
    """
    params:
        encrypt: encryption oracle generated from `gen_encryption_oracle`
        blksize: blocksize used by `encrypt`
    returns:
        blocksize used by `encrypt` and
        size of `randbytes` prepended to message
    """
    encrypted_noinput = encrypt(b'')

    input_bytes = bytes(1)
    encrypted = encrypt(input_bytes)

    i = 0
    while get_block_n(encrypted_noinput, blksize, i) == get_block_n(encrypted, blksize, i):
        i += 1

    prev_block = None
    curr_block = get_block_n(encrypted, blksize, i)
    while curr_block != prev_block:
        input_bytes += b'\x00'
        encrypted = encrypt(input_bytes)
        prev_block = curr_block
        curr_block = get_block_n(encrypted, blksize, i)

    return (blksize*i + (blksize-len(input_bytes)+1))
