import random
import sys


def rand_key_gen(key_size: int = 16) -> bytes:
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
