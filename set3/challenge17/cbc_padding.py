import base64
from Crypto.Cipher import AES
import random
import sys
from typing import Callable, Tuple

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import blocks
from set2.challenge09.pkcs7_padding import *
from set2.challenge10.cbc_mode import CBCMode
from set2.challenge11.rand_enc import rand_bytes_gen
from set2.challenge12.ecb_decrypt import determine_blksize


CONSISTENT_KEY = rand_bytes_gen(16)


def encryption_oracle() -> Tuple[bytes, bytes]:
    """
    params:
        none
    returns:
        ciphertext: one of ten plaintexts encrypted using AES-128-CBC with `iv`
        iv: iv used to encrypt the ciphertext
    """
    plain_strs = (
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIH" +
            b"B1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw" +
            b"==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    )

    blksize = len(CONSISTENT_KEY)

    plain = base64.b64decode(plain_strs[random.randint(0, len(plain_strs)-1)])
    padded = pkcs7_pad(plain, blksize)

    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
    iv = rand_bytes_gen(blksize)
    cbc = CBCMode(
        blksize=blksize,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        iv=iv
    )

    encrypted = cbc.encrypt(padded)

    return encrypted, iv


def valid_padding(encrypted: bytes, iv: bytes) -> bool:
    """
    params:
        encrypted: encrypted message
        iv: IV used to encrypt `encrypted`
    returns:
        True if decryption of `encrypted` has valid padding
        False otherwise
    """
    blksize = len(CONSISTENT_KEY)

    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
    cbc = CBCMode(
        blksize=blksize,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        iv=iv
    )
    decrypted = cbc.decrypt(encrypted)

    try:
        pkcs7_unpad(decrypted)
        return True
    except InvalidPaddingException:
        return False


def get_byte_n(b: bytes, n: int) -> bytes:
    """
    params:
        b
        n
    returns:
        b[n] as a bytes object
    """
    return b[n].to_bytes(1, byteorder=sys.byteorder)


def break_cbc_single_blk(
        cipher_blk1: bytes,
        cipher_blk2: bytes,
        padding_oracle: Callable[[bytes, bytes], bool]) \
        -> bytes:
    """
    params:
        cipher_blk1: encrypted block prior to `cipher_blk2` or IV if
                     `cipher_blk2` was the first encrypted block
        cipher_blk2: block to be decrypted
        padding_oracle: `valid_padding()`
    returns:
        decryption of `cipher_blk2`
    """
    intermediate_blk2 = b''
    plain_blk2 = b''

    for i in range(1, 17):
        target_byte = i.to_bytes(1, byteorder=sys.byteorder)
        atk_blk_prefix = rand_bytes_gen(16-i)
        atk_blk_suffix = b''
        for k in range(len(intermediate_blk2)):
            atk_blk_suffix += xor(target_byte, get_byte_n(intermediate_blk2, k))
        for j in range(256):
            atk_byte = j.to_bytes(1, byteorder=sys.byteorder)
            if valid_padding(cipher_blk2, atk_blk_prefix+atk_byte+atk_blk_suffix):
                break
        intermediate_blk2 = xor(atk_byte, target_byte) + intermediate_blk2
        plain_blk2 = xor(intermediate_blk2, get_byte_n(cipher_blk1, -i)) + plain_blk2

    return plain_blk2


def break_cbc(encrypted: bytes, iv: bytes, padding_oracle: Callable[[bytes, bytes], bool]) \
        -> bytes:
    """
    params:
        encrypted: encrypted message from `encryption_oracle()`
        iv: IV used for encryption from `encryption_oracle()`
        padding_oracle: `valid_padding()`
    returns:
        decrypted bytes for `encrypted`
    """
    decrypted = b''

    prev_blk = iv
    for curr_blk in blocks(encrypted, 16):
        decrypted += break_cbc_single_blk(prev_blk, curr_blk, padding_oracle)
        prev_blk = curr_blk

    return pkcs7_unpad(decrypted)


def main():
    encrypted, iv = encryption_oracle()

    print(break_cbc(encrypted, iv, valid_padding))


if __name__ == "__main__":
    main()
