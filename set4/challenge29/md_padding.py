from __future__ import annotations

from set2.challenge09.pkcs7_padding import InvalidPaddingException


class MDPadding:
    """
    Message Digest padding as specified in RFC 1321
    Notes:
        - This is not a general implementation, it only operates on whole bytes
    """

    @classmethod
    def apply(cls: MDPadding, message: bytes, byteorder: str = "big") \
            -> bytes:
        """
        params:
            message: bytes to be padded
            byteorder: "big" or "little"
        returns:
            padded message
        """
        numbytes = len(message)
        numbits = numbytes * 8
        padded = message + b'\x80'  # Add '1' bit
        padded += b'\x00' * ((56 - ((numbytes+1) % 64)) % 64)  # Add '0' bits
        padded += (numbits % (2 ** 64)).to_bytes(8, byteorder)    # Add length
        return padded

    @classmethod
    def unapply(cls: MDPadding, padded: bytes, byteorder: str = "big") \
            -> bytes:
        """
        params:
            padded: padded message
            byteorder: "big" or "little"
        returns:
            message with padding removed
        """
        numbits = int.from_bytes(padded[-8:], byteorder)
        without_len = padded[:-8]
        i = -1
        while without_len[i] == 0:
            i -= 1
        unpadded = without_len[:i]
        if (len(unpadded) * 8) != numbits:
            raise InvalidPaddingException(
                "Unpadded length does not match expected length"
            )
        return unpadded
