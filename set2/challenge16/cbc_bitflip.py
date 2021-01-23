from Crypto.Cipher import AES
from typing import Callable

from set2.challenge09.pkcs7_padding import *
from set2.challenge10.cbc_mode import *
from set2.challenge11.rand_enc import rand_bytes_gen


CONSISTENT_KEY = rand_bytes_gen(16)
CONSISTENT_IV = rand_bytes_gen(16)


def gen_encryption_oracle(blksize: int = 16, prefix: bytes = None, suffix: bytes = None) \
        -> Callable[[bytes], bytes]:
    """
    params:
        blksize: blocksize `encryption_oracle` should use
        prefix: bytes to prepend to message
        suffix: bytes to append to message
    returns:
        `encryption_oracle` method
    """
    if prefix is None:
        prefix = b"comment1=cooking%20MCs;userdata="

    if suffix is None:
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encryption_oracle(b: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128-CBC
            prepends `prefix` and appends `suffix` before encrypting
        """
        cleaned_data = b.replace(b';', b"';'").replace(b'=', b"'='")

        plain = pkcs7_pad(prefix+cleaned_data+suffix, blksize)
        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)

        return cbc_mode_encrypt(plain, blksize, CONSISTENT_IV, cipher.encrypt)

    return encryption_oracle


def is_admin(encrypted: bytes, blksize: int = 16) -> bool:
    """
    params:
        encrypted: message encrypted using `encryption_oracle()`
        blksize: blocksize used by `encryption_oracle()`
    returns:
        True if decrypted message contains ";admin=true;", False otherwise
    """
    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
    padded = cbc_mode_decrypt(encrypted, blksize, CONSISTENT_IV, cipher.decrypt)
    decrypted = pkcs7_unpad(padded)

    return b";admin=true;" in decrypted
