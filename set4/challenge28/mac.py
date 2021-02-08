from __future__ import annotations

from set4.challenge28.hash import Hash


class MAC:

    @classmethod
    def generate(cls: MAC, plaintext: bytes, key: bytes, hasher: Hash) \
            -> bytes:
        """
        params:
            plaintext: bytes to authenticate
            key: key to use
            hasher: class of a hash implementation
        returns:
            hasher(key || plaintext) || plaintext
        """
        h = hasher()
        h.update(key + plaintext)
        mac = h.digest()
        return mac + plaintext

    @classmethod
    def validate(cls: MAC, message: bytes, key: bytes, hasher: Hash) -> bool:
        """
        params:
            message: plaintext prefixed with MAC
            key: key used to generate MAC
            hasher: class of a hash implementation
        returns:
            True if plaintext matches MAC, False otherwise
        """
        plaintext = message[hasher.digest_size:]
        authenticated = cls.generate(plaintext, key, hasher)
        return authenticated == message
