from collections import defaultdict
from Crypto.Cipher import AES
import random
import sys
from typing import Callable

from set1.challenge07.ecb_mode import ecb_mode, blocks
from set2.challenge09.pkcs7_padding import pkcs7_pad
from set2.challenge10.cbc_mode import cbc_mode


def rand_bytes_gen(key_size: int = 16) -> bytes:
    """
    params:
        key_size: positive integer
    returns:
        `key_size` random bytes
    """
    key = b''
    for i in range(key_size):
        key += random.randint(0, 255).to_bytes(1, byteorder=sys.byteorder)
    return key


def gen_encryption_oracle(blksize: int = 16, use_ecb: bool = None) \
        -> Callable[[bytes], bytes]:
    """
    params:
        blksize: blocksize `encryption_oracle` should use
        use_ecb: True indicates that the `encryption_oracle` should use ECB
                 False indicates that the `encryption_oracle` should use CBC
                 if not specified a mode will be chosen randomly
    returns:
        `encryption_oracle` method
    """
    if use_ecb is None:
        if random.randint(0, 1) == 0:
            use_ecb = True
        else:
            use_ecb = False

    def encryption_oracle(b: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128 with a random key using either
            ECB mode or CBC mode randomly (one in two chance)
            also prepends 5-10 random bytes and appends 5-10 random bytes to
            `b` before encryption
            if CBC mode is used random bytes are used for the IV
        """
        prefix_size = random.randint(5, 10)
        prefix = rand_bytes_gen(prefix_size)
        suffix_size = random.randint(5, 10)
        suffix = rand_bytes_gen(suffix_size)

        plain = pkcs7_pad(prefix+b+suffix, blksize)
        key = rand_bytes_gen(blksize)
        cipher = AES.new(key, AES.MODE_ECB)

        if use_ecb:
            # print("ECB")  # for manual verification
            return ecb_mode(plain, blksize, cipher.encrypt)

        iv = rand_bytes_gen(blksize)

        # print("CBC")
        return cbc_mode(plain, blksize, iv, cipher.encrypt)

    return encryption_oracle


def is_ecb(encrypt: Callable[[bytes], bytes], blksize: int = 16) \
        -> bool:
    """
    params:
        encrypt: encrypts bytes using either ECB or CBC mode
    returns:
        True if `encrypt` used ECB mode, False otherwise
    """
    input_bytes = bytes(blksize*4)   # four blocks of zeroes
    res = encrypt(input_bytes)
    block_count = defaultdict(lambda: 0)
    for block in blocks(res, blksize):
        block_count[block] += 1
        if block_count[block] >= 3:
            return True
    return False


def main():
    """
    run `ecb_cbc_detect()` a few times to check that it works
    """
    for i in range(100):
        print(is_ecb(gen_encryption_oracle()))


if __name__ == "__main__":
    main()
