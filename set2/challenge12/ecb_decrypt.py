import base64
from Crypto.Cipher import AES
from typing import Callable
import sys

from set1.challenge07.ecb_mode import ecb_mode, get_block_n
from set2.challenge09.pkcs7_padding import pkcs7_pad
from set2.challenge11.rand_enc import rand_bytes_gen, is_ecb


CONSISTENT_KEY = rand_bytes_gen(16)

def gen_encryption_oracle(blksize: int = 16) -> Callable[[bytes], bytes]:
    """
    params:
        blksize: blocksize `encryption_oracle` should use
    returns:
        `encryption_oracle` method
    """
    def encryption_oracle(b: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128-ECB
            appends `unknownstr` to `b` before encrypting
        """
        b64bytes = (
            b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            b"YnkK"
        )
        unknownstr = base64.b64decode(b64bytes)

        plain = pkcs7_pad(b+unknownstr, blksize)
        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)

        return ecb_mode(plain, blksize, cipher.encrypt)

    return encryption_oracle


def determine_blksize(encrypt: Callable[[bytes], bytes]) -> int:
    """
    params:
        encrypt: encrypts bytes using ECB mode
    returns:
        blocksize used by `encrypt`
    """
    input_bytes = bytes(1)
    prev_cipher_size = len(encrypt(input_bytes))
    curr_cipher_size = prev_cipher_size
    while curr_cipher_size == prev_cipher_size:
        input_bytes += b'\x00'
        curr_cipher_size = len(encrypt(input_bytes))
    return (curr_cipher_size - prev_cipher_size)


def break_ecb(encrypt: Callable[[bytes], bytes]) -> bytes:
    """
    params:
        encrypt: encryption oracle generated from `gen_encryption_oracle`
    returns:
        `unknownstr` from the `encryption_oracle`
        None if `encrypt` does not use ECB mode
    """
    input_bytes = bytes(1)
    prev_cipher_size = len(encrypt(input_bytes))
    curr_cipher_size = prev_cipher_size
    while curr_cipher_size == prev_cipher_size:
        input_bytes += b'\x00'
        curr_cipher_size = len(encrypt(input_bytes))

    blksize = (curr_cipher_size - prev_cipher_size)
    # copied determine_blksize() to also calculate expected message size
    decrypted_size = prev_cipher_size - len(input_bytes)

    if not is_ecb(encrypt, blksize):
        return None

    numblks = len(encrypt(b''))//blksize
    decrypted = b''

    for i in range(numblks):
        input_bytes = bytes(blksize-1)
        for j in range(blksize):
            enc_blk = get_block_n(encrypt(input_bytes), blksize, i)

            block_to_byte = {}
            for k in range(256):
                b = k.to_bytes(1, byteorder=sys.byteorder)
                last_blk = get_block_n(
                    encrypt(input_bytes+decrypted+b), blksize, i
                )
                block_to_byte[last_blk] = b

            decrypted += block_to_byte.get(enc_blk, b'')
            if len(decrypted) == decrypted_size:
                return decrypted
            input_bytes = input_bytes[:-1]

    return decrypted


def main():
    encryption_oracle = gen_encryption_oracle()

    print(break_ecb(encryption_oracle).decode())


if __name__ == "__main__":
    main()
