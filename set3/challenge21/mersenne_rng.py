def get_n_lowest_bits(e: int, n: int):
    """
    params:
        e: integer from which bits should be obtained
        n: number of bits to retrieve (positive)
    returns:
        `n` lowest order bits of `e`
    """
    if n == 0:
        return 0
    elif n < 0:
        raise ValueError("n should be positive or zero")
    return int(bin(e)[2:][-n:], 2)


class MersenneTwister:
    """
    General Mersenne Twister algorithm implementation
    Parameters are configured for MT19937
    Alternate versions should simply subclass this class and reconfigure the
    parameters in `__init__()`
    reference:
        https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
    """

    def __init__(self):
        self.w = 32     # word size (in number of bits)
        self.n = 624    # degree of recurrence
        self.m = 397    # middle word
        self.r = 31     # separation point of one word
        # coefficients of the rational normal form twist matrix
        self.a = int("0x9908B0DF", 16)
        # TGFSR(R) tempering bitmasks
        self.b = int("0x9D2C5680", 16)
        self.c = int("0xEFC60000", 16)
        # TGFSR(R) tempering bit shifts
        self.s = 7
        self.t = 15
        # additional Mersenne Twister tempering bit shifts/masks
        self.u = 11
        self.d = int("0xFFFFFFFF", 16)
        self.l = 18
        self.f = 1812433253     # generator constant

        self.MT = [0]*self.n
        self.index = self.n+1
        self.lower_mask = (2 ** self.r) - 1     # alternatively: (1 << r) - 1
        self.upper_mask = get_n_lowest_bits(~self.lower_mask, self.w)

    def seed_mt(self, seed: int) -> None:
        """ Initialize the generator from `seed` """
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = get_n_lowest_bits(
                (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i),
                self.w
            )

    def extract_number(self) -> int:
        """
        Extract a tempered value based on MT[index]
        calling `twist()` every `n` numbers
        """
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
            self.twist()

        self.y = self.MT[self.index]
        self.y = self.y ^ ((self.y >> self.u) & self.d)
        self.y = self.y ^ ((self.y << self.s) & self.b)
        self.y = self.y ^ ((self.y << self.t) & self.c)
        self.y = self.y ^ (self.y >> self.l)

        self.index += 1
        return get_n_lowest_bits(self.y, self.w)

    def twist(self):
        """ Generate the next `n` values from the series x_i """
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + \
                (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i+self.m) % self.n] ^ xA
        self.index = 0


class MT19937(MersenneTwister):
    """
    Just a rename
    """
    pass
