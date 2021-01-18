from Crypto.Cipher import AES
import random
import sys

from set1.challenge07.ecb_mode import ecb_mode
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
        return ecb_mode(plain, 16, encrypt)

    iv = rand_bytes_gen(16)

    return cbc_mode(plain, 16, iv, encrypt)
