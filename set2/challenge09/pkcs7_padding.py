import sys


class InvalidPaddingException(Exception):
    pass


def pkcs7_pad(b: bytes, blksize: int) -> bytes:
    """
    params:
        b: bytes to be padded
        blksize: positive integer < 256
    returns:
        `b` padded to `blksize`
        the blocks added have a value equal to the number of blocks added
        if size of `b` is a multiple of `blksize` another block of bytes with
        value `blksize` is added
    """
    if blksize <= 0 or blksize >= 256:
        raise InvalidPaddingException("Invalid block size")

    num_pads = blksize - (len(b) % blksize)
    for i in range(num_pads):
        b += num_pads.to_bytes(1, byteorder=sys.byteorder)
    return b


def pkcs7_unpad(b: bytes) -> bytes:
    """
    params:
        b: bytes that have been padded using pkcs7_pad
    returns:
        `b` without the padding
    raises:
        InvalidPaddingException if `b` is not padded properly
    """
    numbytes = len(b)
    if numbytes == 0:
        return b''

    numpads = b[-1]

    if numpads > numbytes:
        raise InvalidPaddingException
    for i in range(numbytes-numpads, numbytes):
        if b[i] != numpads:
            raise InvalidPaddingException

    return b[:-1*numpads]
