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


def encryption_oracle(b: bytes) -> bytes:
    """
    params:
        b: bytes to encrypt
    returns:
        `b` encrypted using AES-128 with a random key using either
        ECB mode or CBC mode randomly (one in two chance)
        also prepends 5-10 random bytes and appends 5-10 random bytes to `b`
        before encryption
        if CBC mode is used random bytes are used for the IV
    """
    prefix_size = random.randint(5, 10)
    prefix = rand_bytes_gen(prefix_size)
    suffix_size = random.randint(5, 10)
    suffix = rand_bytes_gen(suffix_size)

    plain = pkcs7_pad(prefix+b+suffix, 16)
    key = rand_bytes_gen(16)
    cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(plainbytes: bytes) -> bytes:
        cipherbytes = cipher.encrypt(plainbytes)
        return cipherbytes

    if random.randint(0, 1) == 0:
        print("encrypt: ECB")
        return ecb_mode(plain, 16, encrypt)

    iv = rand_bytes_gen(16)

    print("encrypt: CBC")
    return cbc_mode(plain, 16, iv, encrypt)


def ecb_cbc_detect(fun: Callable[[bytes], bytes]) -> str:
    """
    params:
        fun: encrypts bytes using either ECB or CBC mode
    returns:
        "ECB" if `fun` used ECB mode
        "CBC" otherwise
    """
    input_bytes = bytes(16*4)   # four blocks of zeroes
    res = fun(input_bytes)
    block_count = defaultdict(lambda: 0)
    for block in blocks(res, 16):
        block_count[block] += 1
        if block_count[block] >= 3:
            return "ECB"
    return "CBC"


def main():
    """
    run `ecb_cbc_detect()` a few times to check that it works
    """
    for i in range(100):
        print(ecb_cbc_detect(encryption_oracle))


if __name__ == "__main__":
    main()
