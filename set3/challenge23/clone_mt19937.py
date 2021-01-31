from set3.challenge21.mersenne_rng import MT19937


def get_numbits(e: int):
    """
    params:
        e: positive integer
    returns:
        number of bits to represent `e`
    """
    res = 0
    while e > 0:
        res += 1
        e >>= 1
    return res


def keep_bitrange(e: int, low: int, high: int) -> int:
    """
    params:
        e: positive integer
        low: lowest bit that should be kept, 1-indexed (positive)
        high: highest bit that should be kept, 1-indexed (> `low`)
    returns:
        `e` with all bits outside of [low, high] range zeroed-out
    """
    if high < low:
        raise ValueError("high must be greater than low")
    mask = (1 << (high-low+1)) - 1
    mask <<= low-1
    return e & mask


def _untemper_right(bits: int, shift: int, mask: int) -> int:
    """
    params:
        bits: bits to untemper
        shift: amount of right shifting done by the tempering (positive)
        mask: mask applied by tempering
    returns:
        x such that x = bits ^ ((bits >> shift) & mask)
    """
    if shift < 0:
        raise ValueError("shift must be positive")

    res = 0
    numbits = get_numbits(bits)

    prev_bits = keep_bitrange(bits, numbits-shift+1, numbits)
    res += prev_bits
    index = 1
    while numbits-(shift*index) > 0:
        low = numbits-(shift*(index+1))+1
        if low <= 0:
            low = 1
        high = numbits-(shift*index)
        curr_bits = keep_bitrange(bits, low, high)
        and_mask = keep_bitrange(mask, low, high)
        xor_mask = (prev_bits >> shift) & and_mask
        prev_bits = curr_bits ^ xor_mask
        res += prev_bits
        index += 1
    return res
