import base64
from Crypto.Cipher import AES
import pathlib
import os

from set2.challenge10.cbc_mode import CBCMode


def main():
    """
    decrypt contents of a file encrypted using AES-128 in CBC mode
    """
    key = b"YELLOW SUBMARINE"
    iv = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    cbc = CBCMode(16, cipher.encrypt, cipher.decrypt, iv=iv)

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, 'r') as input_file:
        base64_str = input_file.read()
    base64_bytes = base64_str.replace('\n', '').encode("utf-8")
    encrypted = base64.decodebytes(base64_bytes)

    message = cbc.decrypt(encrypted)

    print(message.decode("utf-8", errors="ignore"))


if __name__ == "__main__":
    main()
