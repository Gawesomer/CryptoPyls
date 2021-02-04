import base64
from Crypto.Cipher import AES
import os
import pathlib
from typing import Callable

from set1.challenge07.ecb_mode import ECBMode
from set2.challenge11.rand_enc import rand_bytes_gen
from set3.challenge18.ctr_mode import CTRMode


def gen_edit_oracle(key: bytes, nonce: bytes) \
        -> Callable[[bytes, int, bytes], bytes]:
    """
    params:
        key: key used by encryption
        nonce: nonce used by encryption
    returns:
        `edit_oracle` method
    """
    def edit_oracle(ciphertext: bytes, offset: int, newtext: bytes) -> bytes:
        """
        params:
            ciphertext: encrypted using AES-128 in CTR Mode with `key`
            offset: index at which `newtext` should be insterted
                    if offset too large, will simply append `newtext`
                    if offset < 0, will simply prepend `newtext`
            newtext: bytes to be inserted
        returns:
            `ciphertext` re-encrypted with `newtext` inserted at `offset`
        """
        cipher = AES.new(key, AES.MODE_ECB)
        ctr = CTRMode(
            blksize=16,
            encrypt_blk=cipher.encrypt,
            decrypt_blk=cipher.decrypt,
            nonce=nonce,
        )

        plaintext = ctr.decrypt(ciphertext)
        new_plaintext = plaintext[:offset] + newtext + plaintext[offset:]

        return ctr.encrypt(new_plaintext)

    return edit_oracle


def main():
    """
    decrypt contents of a file encrypted using AES-128 in ECB Mode
    encrypt decrypted plaintext using AES-128 in CTR Mode
    """
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)
    ecb = ECBMode(16, cipher.encrypt, cipher.decrypt)

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, "r") as input_file:
        base64_str = input_file.read()
    base64_bytes = base64_str.replace('\n', '').encode("utf-8")
    ecb_encrypted = base64.decodebytes(base64_bytes)

    plaintext = ecb.decrypt(ecb_encrypted)

    nonce = bytes(8)
    unknown_key = rand_bytes_gen(16)
    cipher = AES.new(unknown_key, AES.MODE_ECB)

    ctr = CTRMode(
        blksize=16,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        nonce=nonce
    )

    encrypted = ctr.encrypt(plaintext)
    print(encrypted)


if __name__ == "__main__":
    main()
