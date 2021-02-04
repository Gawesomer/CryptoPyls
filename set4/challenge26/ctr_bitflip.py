from Crypto.Cipher import AES
from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import get_block_n
from set2.challenge11.rand_enc import rand_bytes_gen
from set3.challenge18.ctr_mode import CTRMode


CONSISTENT_KEY = rand_bytes_gen(16)
CONSISTENT_NONCE = rand_bytes_gen(8)


# Copied from set2.challenge16.ctr_bitflip
# Very specific use-case so I chose to copy instead of refactoring with
# greater abstraction
# No need to retest (Famous last words :P)
# Changed to use CTRMode
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
            `b` encrypted using AES-128-CTR
            prepends `prefix` and appends `suffix` before encrypting
        """
        cleaned_data = b.replace(b';', b"';'").replace(b'=', b"'='")

        plain = prefix + cleaned_data + suffix
        cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=blksize,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=CONSISTENT_NONCE,
        )

        return ctr.encrypt(plain)

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
    ctr = CTRMode(
        blksize=blksize,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        nonce=CONSISTENT_NONCE,
    )
    decrypted = ctr.decrypt(encrypted)

    return b";admin=true;" in decrypted


def main():
    """
    insert ";admin=true;" string inside encrypted message using only
    `encryption_oracle()`
    """
    encryption_oracle = gen_encryption_oracle()

    desired_plaintext = b";admin=true;"

    # `encryption_oracle()` prepends exactly two blocks
    # feed some zeroes to figure out the key-cipher for the third block
    encrypted = encryption_oracle(bytes(len(desired_plaintext)))
    keycipher_block3 = get_block_n(encrypted, 16, 2)

    # knowing the key cipher it's easy to figure out what input we should feed
    # to get the decryption we desire
    attack_block = xor(desired_plaintext, keycipher_block3)

    attack_encrypted = encrypted[:32] + attack_block + \
        encrypted[32+len(desired_plaintext):]

    print(is_admin(attack_encrypted))


if __name__ == "__main__":
    main()
