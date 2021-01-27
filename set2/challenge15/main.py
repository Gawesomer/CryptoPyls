from set2.challenge09.pkcs7_padding import pkcs7_unpad, InvalidPaddingException


def main():
    """
    Already implemented `pkcs7_unpad()` in set2.challenge09
    Display that it solves the challenge
    """
    b = b"ICE ICE BABY\x04\x04\x04\x04"
    print("pkcs7_unpad(%s):" % b)
    print(pkcs7_unpad(b))

    b = b"ICE ICE BABY\x05\x05\x05\x05"
    print("pkcs7_unpad(%s):" % b)
    try:
        pkcs7_unpad(b)
    except (InvalidPaddingException):
        print("Exception raised")

    b = b"ICE ICE BABY\x01\x02\x03\x04"
    print("pkcs7_unpad(%s):" % b)
    try:
        pkcs7_unpad(b)
    except (InvalidPaddingException):
        print("Exception raised")


if __name__ == "__main__":
    main()
