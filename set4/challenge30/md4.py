# MD4 Python 3 implementation
# Copyright (C) 2013  Filippo Valsorda
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Originally based, even if no code survives, on a LGPL work by
# Dmitry Rozmanov <dima@xenon.spb.ru> 2002
# http://www.geocities.com/rozmanov/python/

# Taken from: https://github.com/FiloSottile/crypto.py

import struct
import binascii

from set4.challenge28.sha1 import _left_rotate


class MD4():

    def __init__(self):
        self.A, self.B, self.C, self.D = (
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476
        )
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def update(self, message):
        message_byte_length = self._message_byte_length + len(message)
        message_bit_length = message_byte_length * 8
        length = struct.pack('<Q', message_bit_length)
        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]
        message += b'\x80'
        message += bytes((56 - (message_byte_length+1) % 64) % 64)
        message += length
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _F(self, x, y, z):
        return ((x & y) | (~x & z))

    def _G(self, x, y, z):
        return ((x & y) | (x & z) | (y & z))

    def _H(self, x, y, z):
        return (x ^ y ^ z)

    def _handle(self, chunk):
        X = list(struct.unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = _left_rotate((A + self._F(B, C, D) + X[k]), 3)
            elif i % 4 == 1:
                D = _left_rotate((D + self._F(A, B, C) + X[k]), 7)
            elif i % 4 == 2:
                C = _left_rotate((C + self._F(D, A, B) + X[k]), 11)
            elif i % 4 == 3:
                B = _left_rotate((B + self._F(C, D, A) + X[k]), 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = _left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999), 3)
            elif i % 4 == 1:
                D = _left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999), 5)
            elif i % 4 == 2:
                C = _left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999), 9)
            elif i % 4 == 3:
                B = _left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999), 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = _left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1), 3)
            elif i % 4 == 1:
                D = _left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1), 9)
            elif i % 4 == 2:
                C = _left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1), 11)
            elif i % 4 == 3:
                B = _left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1), 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return struct.pack('<IIII', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()
