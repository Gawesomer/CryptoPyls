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


def main():
    """
    insert ";admin=true;" string inside encrypted message using only
    `encryption_oracle()`
    """
    encryption_oracle = gen_encryption_oracle()

    # `encryption_oracle()` prepends exactly two blocks
    # add two blocks of our own, the first block will be used to mutate the
    # second one to our desired string
    plain2 = bytes(16)
    plain3 = bytes(16)
    hack_enc = encryption_oracle(plain2+plain3)
    hack_enc_blocks = [b for b in blocks(hack_enc, 16)]

    # knowing the blocks that are getting encrypted (we just picked them above)
    # we can figure out the AES decryption of the second block we added
    decrypted_block3 = xor(hack_enc_blocks[2], plain3)

    # the AES decryption of our block will get XORed with the previous block
    # (i.e. the first block we added)
    # simply XOR decrypted and desired to figure out what first block we need
    # to use to mutate the second block as desired
    desired_block = b"\x00\x00\x00\x00;admin=true;"
    encrypted2 = xor(decrypted_block3, desired_block)

    # remix the encrypted message by replacing the encrypted block of the first
    # block we added with the block that will give us the required mutation
    # all other blocks can remain the same as changing one block will only
    # mutate the decryption of the next one and won't change the ones further
    # down (i.e. not risk of ruining the padding down the line)
    encrypted = hack_enc_blocks[0] + hack_enc_blocks[1] + encrypted2
    for i in range(3, len(hack_enc_blocks)):
        encrypted += hack_enc_blocks[i]

    print(is_admin(encrypted))


if __name__ == "__main__":
    main()
