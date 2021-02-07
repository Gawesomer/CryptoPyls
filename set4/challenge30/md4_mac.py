from set4.challenge30.md4 import MD4


def authenticate_message(plaintext: bytes, key: bytes) -> bytes:
    """
    params:
        plaintext: plaintext to authenticate
    returns:
        `MD4(key || plaintext) || plaintext`
    """
    h = MD4(key + plaintext)
    mac = h.digest()
    return mac + plaintext


def is_valid_message(message: bytes, key: bytes) -> bool:
    """
    params:
        message: plaintext prefixed by MD4-MAC
        key: key used to generate MAC
    returns:
        True if plaintext matches MAC, False otherwise
    """
    plaintext = message[16:]
    authenticated = authenticate_message(plaintext, key)
    return authenticated == message
