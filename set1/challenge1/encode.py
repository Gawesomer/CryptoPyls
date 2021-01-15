import base64


def hextob64(hexstr: str) -> bytes:
    """
    params:
        hexstr: must contain two hexadecimal digits per byte
    returns:
        base64 encoding of `hexstr`
    raises:
        TypeError if `hexstr` is None
        ValueError if `hexstr` is improperly formatted
    """
    binary = bytes.fromhex(hexstr)
    return base64.b64encode(binary)


def b64tohex(b64bytes: bytes) -> str:
    """
    params:
        b64bytes: base64 encoded bytes
    returns:
        hex translation of `b64bytes`
    raises:
        TypeError if `b64bytes` if None
        binascii.Error exception if `b64bytes` is incorrectly padded
    """
    binary = base64.b64decode(b64bytes)
    return bytes.hex(binary)
