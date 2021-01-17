import sys


def pkcs7_pad(b: bytes, blk_size: int) -> bytes:
    """
    params:
        b: bytes to be padded
        blk_size: positive integer < 256
    returns:
        `b` padded to `blk_size`
        the blocks added have a value equal to the number of blocks added
        if size of `b` is a multiple of `blk_size` another block of bytes with
        value `blk_size` is added
    """
    if blk_size <= 0 or blk_size >= 256:
        return b

    num_pads = blk_size - (len(b) % blk_size)
    for i in range(num_pads):
        b += num_pads.to_bytes(1, byteorder=sys.byteorder)
    return b
