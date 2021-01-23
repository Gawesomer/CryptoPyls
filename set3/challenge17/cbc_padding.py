import base64
from Crypto.Cipher import AES
import random
from typing import Tuple

from set2.challenge09.pkcs7_padding import *
from set2.challenge10.cbc_mode import *
from set2.challenge11.rand_enc import rand_bytes_gen


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

    encrypted = cbc_mode_encrypt(padded, blksize, iv, cipher.encrypt)

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
    decrypted = cbc_mode_decrypt(encrypted, blksize, iv, cipher.decrypt)

    try:
        pkcs7_unpad(decrypted)
        return True
    except InvalidPaddingException:
        return False
