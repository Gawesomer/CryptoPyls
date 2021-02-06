from __future__ import annotations
import sys


class InvalidPaddingException(Exception):
    pass


class PKCS7Padding:
    """
    PKCS7 padding as described in RFC 2315
    """

    @classmethod
    def apply(cls: PKCS7Padding, message: bytes, blksize: int) -> bytes:
        """
        params:
            message: bytes to be padded
            blksize: positive integer < 256
        returns:
            `message` padded to `blksize`
            the blocks added have a value equal to the number of blocks added
            if size of `message` is a multiple of `blksize` another block of
            bytes with value `blksize` is added
        """
        if blksize <= 0 or blksize >= 256:
            raise InvalidPaddingException("Invalid block size")

        num_pads = blksize - (len(message) % blksize)
        for i in range(num_pads):
            message += num_pads.to_bytes(1, byteorder=sys.byteorder)
        return message

    @classmethod
    def unapply(cls: PKCS7Padding, padded: bytes) -> bytes:
        """
        params:
            padded: bytes that have been padded using PKCS7Padding
        returns:
            `padded` without the padding
        raises:
            InvalidPaddingException if `padded` is not padded properly
        """
        numbytes = len(padded)
        if numbytes == 0:
            return b''

        numpads = padded[-1]

        if numpads > numbytes or numpads <= 0:
            raise InvalidPaddingException
        for i in range(numbytes-numpads, numbytes):
            if padded[i] != numpads:
                raise InvalidPaddingException

        return padded[:-1*numpads]
