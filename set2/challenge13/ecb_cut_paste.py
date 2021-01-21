from Crypto.Cipher import AES

from set1.challenge07.ecb_mode import ecb_mode
from set2.challenge09.pkcs7_padding import *
from set2.challenge11.rand_enc import rand_bytes_gen
from set2.challenge13.cookie import *


CONSISTENT_KEY = rand_bytes_gen(16)


def profile_for(email: str) -> str:
    """
    params:
        email: does not allow for '&' or '=' those characters are removed
    returns:
        encoded cookie representing a user profile with the given email
    """
    clean_email = email.replace('&', '').replace('=', '')
    profile = {
      'email': clean_email,
      'uid': 10,
      'role': 'user'
    }

    return encode_cookie(profile)


def encrypt_profile(profile: str) -> bytes:
    """
    params:
        profile: encoded profile
    returns:
        `profile` encrypted using AES-128 ECB mode with a consistent key
    """
    blksize = 16
    plain = pkcs7_pad(profile.encode(), blksize)
    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)

    return ecb_mode(plain, blksize, cipher.encrypt)


def decrypt_profile(encrypted: bytes) -> str:
    """
    params:
        encrypted: profile encrypted using `encrypted_profile()`
    returns:
        encoded profile
    """
    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
    padded = ecb_mode(encrypted, 16, cipher.decrypt)

    return pkcs7_unpad(padded).decode()
