from __future__ import annotations

import struct


class MDPadding:
    """
    Message Digest padding as specified in RFC 1321
    """

    @classmethod
    def apply(cls: MDPadding, message: bytes) -> bytes:
        """
        params:
            message: bytes to be padded
        returns:
            padded message
        """
        numbytes = len(message)
        numbits = numbytes * 8
        padded = message + b'\x80'  # Add '1' bit
        padded += b'\x00' * ((56 - ((numbytes+1) % 64)) % 64)  # Add '0' bits
        padded += (numbits % (2 ** 64)).to_bytes(8, "big")    # Add length
        return padded


    @classmethod
    def unapply(cls: MDPadding, padded: bytes) -> bytes:
        """
        params:
            padded: padded message
        returns:
            message with padding removed
        """
        pass
