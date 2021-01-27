from Crypto.Cipher import AES

from set1.challenge07.ecb_mode import ECBMode, get_block_n
from set2.challenge09.pkcs7_padding import pkcs7_pad, pkcs7_unpad
from set2.challenge11.rand_enc import rand_bytes_gen
from set2.challenge13.cookie import decode_cookie, encode_cookie


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
    ecb = ECBMode(blksize, cipher.encrypt, cipher.decrypt)

    return ecb.encrypt(plain)


def decrypt_profile(encrypted: bytes) -> str:
    """
    params:
        encrypted: profile encrypted using `encrypted_profile()`
    returns:
        encoded profile
    """
    cipher = AES.new(CONSISTENT_KEY, AES.MODE_ECB)
    ecb = ECBMode(16, cipher.encrypt, cipher.decrypt)

    padded = ecb.decrypt(encrypted)

    return pkcs7_unpad(padded).decode()


def main():
    """
    build an admin profile
    this must be done only by using `encrypt_profile(profile_for(input))`
    i.e. we may only control `input`
    """
    trap_email = "10_PADDINGadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    encrypted = encrypt_profile(profile_for(trap_email))
    admin_block = get_block_n(encrypted, 16, 1)
    valid_email = "haha_you.just_got?@hacked.com"
    encrypted = encrypt_profile(profile_for(valid_email))

    admin_profile_encrypted = get_block_n(encrypted, 16, 0) + \
        get_block_n(encrypted, 16, 1) + get_block_n(encrypted, 16, 2) + \
        admin_block

    print(decode_cookie(decrypt_profile(admin_profile_encrypted)))


if __name__ == "__main__":
    main()
