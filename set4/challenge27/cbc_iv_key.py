from Crypto.Cipher import AES
from typing import Callable

from set1.challenge02.fixed_xor import xor
from set1.challenge07.ecb_mode import blocks, get_block_n
from set2.challenge09.pkcs7_padding import PKCS7Padding
from set2.challenge10.cbc_mode import CBCMode


def gen_encryption_method(key: bytes, blksize: int = 16) \
        -> Callable[[bytes], bytes]:
    """
    params:
        key: key to use for encryption
        blksize: blocksize `encryption_oracle` should use
    returns:
        `aes_cbc` method
    """
    def aes_cbc(plaintext: bytes) -> bytes:
        """
        params:
            b: bytes to encrypt
        returns:
            `b` encrypted using AES-128-CBC
            uses key as IV
        """
        padded = PKCS7Padding.apply(plaintext, blksize)
        cipher = AES.new(key, AES.MODE_ECB)
        cbc = CBCMode(
            blksize=blksize,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            iv=key,
        )

        return cbc.encrypt(padded)

    return aes_cbc


def gen_ascii_oracle(key: bytes, blksize: int = 16) \
        -> Callable[[bytes], bytes]:
    """
    params:
        key: key used for decryption
        blksize: blocksize used for decryption
    returns:
        `validate_ascii` method
    """
    def validate_ascii(encrypted: bytes) -> bytes:
        """
        params:
            encrypted: message encrypted using `aes_cbc()`
        returns:
            decrypted bytes if they contain extended ascii characters,
            None otherwise
        """
        cipher = AES.new(key, AES.MODE_ECB)
        cbc = CBCMode(
            blksize=blksize,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            iv=key
        )
        padded = cbc.decrypt(encrypted)
        decrypted = PKCS7Padding.unapply(padded)

        for c in decrypted:
            if c >= 128:
                return decrypted
        return None

    return validate_ascii


def recover_key(ciphertext: bytes,
                ascii_oracle: Callable[[bytes], None],
                blksize: int = 16) \
                -> bytes:
    """
    params:
        ciphertext: encrypted using `encryption_method()` must be at least
                    three blocks long
        ascii_oracle: `validate_ascii()`
        blksize: blocksize used by encryption
    returns:
        key used by encryption, or None if less than three bytes were given
    """
    ciphertext_blocks = [block for block in blocks(ciphertext, blksize)]
    if len(ciphertext_blocks) < 3:
        return None

    # append last two blocks to maintain valid padding
    attack_ciphertext = ciphertext_blocks[0] + bytes(blksize) + \
        ciphertext_blocks[0] + ciphertext_blocks[-2] + ciphertext_blocks[-1]

    decrypted = ascii_oracle(attack_ciphertext)
    if decrypted:
        return xor(get_block_n(decrypted, blksize, 0),
                   get_block_n(decrypted, blksize, 2))
    return None
