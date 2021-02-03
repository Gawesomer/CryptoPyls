from __future__ import annotations

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
        x such that bits = x ^ ((x >> shift) & mask)
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


def _untemper_left(bits: int, shift: int, mask: int) -> int:
    """
    params:
        bits: bits to untemper
        shift: amount of left shifting done by the tempering (positive)
        mask: mask applied by tempering
    returns:
        x such that bits = x ^ ((x << shift) & mask)
    """
    if shift < 0:
        raise ValueError("shift must be positive")

    res = 0
    numbits = max(get_numbits(bits), get_numbits(mask))

    prev_bits = keep_bitrange(bits, 1, shift)
    res += prev_bits
    index = 1
    while (shift*index)+1 <= numbits:
        low = (shift*index)+1
        high = (shift*(index+1))
        curr_bits = keep_bitrange(bits, low, high)
        and_mask = keep_bitrange(mask, low, high)
        xor_mask = (prev_bits << shift) & and_mask
        prev_bits = curr_bits ^ xor_mask
        res += prev_bits
        index += 1
    return res


def untemper(tempered: int,
             u: int = 11, d: int = 0xFFFFFFFF,
             s: int = 7, b: int = 0x9D2C5680,
             t: int = 15, c: int = 0xEFC60000,
             l: int = 18) \
                -> int:
    """
    params:
        tempered: bits to untemper
        u, d, s, b, t, c, l: parameters used for tempering
                             (defaults set for MT19937)
    returns:
        x such that:
            tempered = x ^ ((x >> u) & d)
            tempered = tempered ^ ((tempered << s) & b)
            tempered = tempered ^ ((tempered << t) & c)
            tempered = tempered ^ (tempered >> l)
    """
    res = _untemper_right(tempered, l, (1 << get_numbits(tempered)) - 1)
    res = _untemper_left(res, t, c)
    res = _untemper_left(res, s, b)
    res = _untemper_right(res, u, d)

    return res


def clone_mt19937(mt: MT19937) -> MT19937:
    """
    params:
        mt: seeded MT19937 generator
    returns:
        cloned MT19937 with state spliced from that of `mt`
    side-effect:
        `mt` will have been tapped 624 times
    """
    cloned = MT19937()

    cloned.index = 0
    for i in range(mt.n):
        cloned.MT[i] = untemper(mt.extract_number())

    return cloned
