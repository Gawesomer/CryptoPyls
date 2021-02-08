from __future__ import annotations


class Hash:
    """
    Interface for hashing algorithms
    """

    digest_size = 0     # size of generated hash in bytes
    block_size = 0      # blocksize in bytes

    def update(self: Hash, message: bytes):
        raise NotImplementedError

    def digest(self: Hash) -> bytes:
        raise NotImplementedError
