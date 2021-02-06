from Crypto.Hash import SHA1


def authenticate_message(plaintext: bytes, key: bytes) -> bytes:
    """
    params:
        plaintext: plaintext to authenticate
    returns:
        `SHA1(key || plaintext) || plaintext`
    """
    h = SHA1.new()
    h.update(key + plaintext)
    mac = h.digest()
    return mac + plaintext


def is_valid_message(message: bytes, key: bytes) -> bool:
    """
    params:
        message: plaintext prefixed by SHA1-MAC
        key: key used to generate MAC
    returns:
        True if plaintext matches MAC, False otherwise
    """
    plaintext = message[20:]
    authenticated = authenticate_message(plaintext, key)
    return authenticated == message