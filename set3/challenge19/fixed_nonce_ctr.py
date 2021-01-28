import base64
from Crypto.Cipher import AES
import os
import pathlib

from set1.challenge02.fixed_xor import xor
from set1.challenge06.break_repeat_xor import break_repeat_xor
from set3.challenge18.ctr_mode import CTRMode


def ctr_encrypt_b64(b64: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    params:
        b64: base64 encoded bytes to be encrypted
        nonce: nonce to be used for CTR
        key: key to be used for encryption
    returns:
        `b64` encrypted using AES with CTR
    """
    binary = base64.b64decode(b64)

    cipher = AES.new(key, AES.MODE_ECB)
    ctr = CTRMode(
        blksize=16,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        nonce=nonce,
    )

    return ctr.encrypt(binary)


def main():
    """
    encrypt base64 encoded strings from file with consistent nonce
    break decryption by using `break_repeat_xor()` to get as much of the key
    as possible
    fix key by XORing encrypted messages with the decryption that has been made
    apparent
    """
    encrypted_lines = []
    key = b"YELLOW SUBMARINE"
    nonce = bytes(8)

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, "r") as input_file:
        for line in input_file:
            encrypted_lines.append(ctr_encrypt_b64(line, key, nonce))

    repeat_xor_cipher = b''
    blksize = 31
    for line in encrypted_lines:
        if len(line) >= blksize:
            repeat_xor_cipher += line[:blksize]

    res = break_repeat_xor(repeat_xor_cipher, blksize)
    key = res["key"]

    max_len = max([len(line) for line in encrypted_lines])

    key = xor(b"I have met them at close of day", encrypted_lines[0])
    key += bytes(max_len-len(key))
    key = xor(b"I have passed with a nod of the head", encrypted_lines[4])
    key += bytes(max_len-len(key))
    key = xor(b"He, too, has been changed in his turn,", encrypted_lines[37])
    key += bytes(max_len-len(key))

    for line in encrypted_lines:
        print(xor(key, line).decode())


if __name__ == "__main__":
    main()
