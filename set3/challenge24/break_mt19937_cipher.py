import random

from set2.challenge11.rand_enc import rand_bytes_gen
from set3.challenge24.mt19937_cipher import MT19937Cipher


def gen_ciphertext(plaintext: bytes, seed: int) -> bytes:
    """
    params:
        plaintext: bytes to encrypt
        seed: seed to use for encryption
    returns:
        MT19937Cipher encryption of `plaintext` prepended with a random number
        of random bytes using a random seed of 16 bytes
    """
    cipher = MT19937Cipher(seed)
    prefix = rand_bytes_gen(random.randint(1, 255))

    return cipher.encrypt(prefix+plaintext)


def recover_key(plaintext: bytes, ciphertext: bytes, keysize: int = 16) -> int:
    """
    params:
        plaintext: known plaintext
        ciphertext: `plaintext` encrypted with `gen_ciphertext`
        keysize: max size of key in bits
    returns:
        seed used by encryption
        None if seed not found
    """
    for seed in range(2**keysize):
        cipher = MT19937Cipher(seed)
        decrypted = cipher.decrypt(ciphertext)
        if decrypted.endswith(plaintext):
            return seed
    return None
