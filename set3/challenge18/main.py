import base64
from Crypto.Cipher import AES

from set3.challenge18.ctr_mode import CTRMode


def main():
    """
    decrypt string encrypted using CTRMode
    """
    b64 = (b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvo"
           b"OLSFQ==")
    binary = base64.b64decode(b64)

    key = b"YELLOW SUBMARINE"
    nonce = bytes(8)
    cipher = AES.new(key, AES.MODE_ECB)
    ctr = CTRMode(
        blksize=16,
        encrypt_blk=cipher.encrypt,
        decrypt_blk=cipher.decrypt,
        nonce=nonce,
    )

    decrypted = ctr.decrypt(binary)

    print(decrypted.decode())


if __name__ == "__main__":
    main()
