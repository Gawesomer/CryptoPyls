from set2.challenge09.pkcs7_padding import PKCS7Padding, \
    InvalidPaddingException


def main():
    """
    Already implemented `PKCS7Padding.unapply()` in set2.challenge09
    Display that it solves the challenge
    """
    b = b"ICE ICE BABY\x04\x04\x04\x04"
    print("PKCS7Padding.unapply(%s):" % b)
    print(PKCS7Padding.unapply(b))

    b = b"ICE ICE BABY\x05\x05\x05\x05"
    print("PKCS7Padding.unapply(%s):" % b)
    try:
        PKCS7Padding.unapply(b)
    except (InvalidPaddingException):
        print("Exception raised")

    b = b"ICE ICE BABY\x01\x02\x03\x04"
    print("PKCS7Padding.unapply(%s):" % b)
    try:
        PKCS7Padding.unapply(b)
    except (InvalidPaddingException):
        print("Exception raised")


if __name__ == "__main__":
    main()
