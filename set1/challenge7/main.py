import base64
from Crypto.Cipher import AES
import pathlib
import os


def main():
    """
    decrypt contents of a file encrypted using AES-128 in ECB mode
    """
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, 'r') as input_file:
        base64_str = input_file.read()
    base64_bytes = base64_str.replace('\n', '').encode("utf-8")
    encrypted = base64.decodebytes(base64_bytes)

    message = cipher.decrypt(encrypted)

    print(message.decode())


if __name__ == "__main__":
    main()
