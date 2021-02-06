import base64
from Crypto.Cipher import AES
import random
import sys
from typing import Callable

from set1.challenge07.ecb_mode import ECBMode, get_block_n
from set2.challenge09.pkcs7_padding import PKCS7Padding
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
        randbytes = rand_bytes_gen(random.randint(0, 255))

    def encryption_oracle(b: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128-ECB
            appends `unknownstr` and prepends consistent random bytes to `b`
            before encrypting
        """
        plain = PKCS7Padding.apply(randbytes+b+unknownstr, blksize)
        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
        ecb = ECBMode(blksize, cipher.encrypt, cipher.decrypt)

        return ecb.encrypt(plain)

    return encryption_oracle


def determine_randbytes_size(encrypt: Callable[[bytes], bytes], blksize: int) \
        -> int:
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

    randbytes_size = determine_randbytes_size(encrypt, blksize)

    # copied determine_blksize() to also calculate expected message size
    decrypted_size = prev_cipher_size - len(input_bytes) - randbytes_size

    if not is_ecb(encrypt, blksize):
        return None

    numblks = len(encrypt(b''))//blksize
    decrypted = b''

    offset = (randbytes_size//blksize)+1
    for i in range(numblks):
        input_bytes = bytes(blksize-(randbytes_size % blksize)+blksize-1)
        for j in range(blksize):
            enc_blk = get_block_n(encrypt(input_bytes), blksize, i+offset)

            block_to_byte = {}
            for k in range(256):
                b = k.to_bytes(1, byteorder=sys.byteorder)
                last_blk = get_block_n(
                    encrypt(input_bytes+decrypted+b), blksize, i+offset
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
