# 32-bit constants
kl1 = tuple([int((n ** (1 / 2)) * (1 << 30)) for n in [0, 2, 3, 5]])
kr1 = tuple([int((n ** (1 / 3)) * (1 << 30)) for n in [2, 3, 5, 0]])
# kl = (0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc)
# kr = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000)


kl2 = tuple([int((n ** (1 / 2)) * (1 << 30)) for n in [0, 2, 3, 5, 7]])
kr2 = tuple([int((n ** (1 / 3)) * (1 << 30)) for n in [2, 3, 5, 7, 0]])
# kl = (0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e)
# kr = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000)

# selections of message words
zl = [
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
]

# selections of message words
zr = [
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
]

# left rotation offsets
sl = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
]

# left rotation offsets 
sr = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
]

# non-linear boolean functions
r_func = [
    lambda x, y, z: x ^ y ^ z,              #  0 <= i <= 15
    lambda x, y, z: (x & y) | (~x & z),     # 16 <= i <= 31
    lambda x, y, z: (x | ~y) ^ z,           # 32 <= i <= 47
    lambda x, y, z: (x & z) | (y & ~z),     # 48 <= i <= 63
    lambda x, y, z: x ^ (y | ~z)            # 64 <= i <= 80
]

# Rotate Left (ROL)
rol = lambda w, s: (w >> (32 - s)) | ((w << s) & 0xffffffff)


class RIPEMD_128:
    def __init__(self):
        # initial values
        self.iv = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    def get_blocks(self, message_bytes):
        blocks = []
        # divide the message into successive 512-bit blocks
        for i in range(0, len(message_bytes), 64):
            block = []
            for j in range(16):
                block.append(int.from_bytes(message_bytes[i + j * 4: i + j * 4 + 4], 'little'))
            blocks.append(block)
        return blocks

    def padding(self, message_bytes):
        # original message length
        message_byte_length = len(message_bytes)
        # append padding bits until message byte length ≡ 56 mod 64
        message_bytes += b'\x80' + b'\x00' * ((55 - message_byte_length) % 64)
        # append original message length (little-endian)
        message_bytes += (message_byte_length * 8).to_bytes(8, byteorder='little')
        return message_bytes

    def compression_func(self, cv, block):
        # buffer
        bl = cv.copy()
        br = cv.copy()
        for i in range(64):
            bl = [
                bl[3],
                rol((bl[0] + r_func[i // 16](bl[1], bl[2], bl[3]) + block[zl[i]] + kl1[i // 16]) & 0xffffffff, sl[i]),
                bl[1],
                bl[2]
            ]
            br = [
                br[3],
                rol((br[0] + r_func[(63 - i) // 16](br[1], br[2], br[3]) + block[zr[i]] + kr1[i // 16]) & 0xffffffff, sr[i]),
                br[1],
                br[2]
            ]
        return bl, br

    def hash(self, message_bytes):
        # chaining variables
        cv = self.iv.copy()
        # message blocks
        blocks = self.get_blocks(self.padding(message_bytes))

        for z, block in enumerate(blocks):
            # print(z)
            bl, br = self.compression_func(cv, block)
            # bitwise addition
            cv = [(cv[i + 1 - len(cv)] + bl[i + 2 - len(cv)] + br[i + 3 - len(cv)]) & 0xffffffff for i in range(len(cv))]

            # cv = [(cv[i - 3] + bl[i - 2] + br[i - 1]) & 0xffffffff for i in range(len(cv))]
        # big-endian output
        for i in range(len(cv)):
            cv[i] = int.from_bytes(cv[i].to_bytes(4, byteorder='little'), byteorder='big')
        # hex format
        return ''.join([hex(h)[2:].zfill(8) for h in cv])


class RIPEMD_160(RIPEMD_128):
    def __init__(self):
        super(RIPEMD_128, self).__init__()
        # initial values
        self.iv = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    def compression_func(self, cv, block):
        # buffer
        bl = cv.copy()
        br = cv.copy()
        for i in range(80):
            bl = [
                bl[4],
                (bl[4] + rol((bl[0] + r_func[i // 16](bl[1], bl[2], bl[3]) + block[zl[i]] + kl2[i // 16]) & 0xffffffff, sl[i])) & 0xffffffff,
                bl[1],
                rol(bl[2], 10),
                bl[3]
            ]
            br = [
                br[4],
                (br[4] + rol((br[0] + r_func[(79 - i) // 16](br[1], br[2], br[3]) + block[zr[i]] + kr2[i // 16]) & 0xffffffff, sr[i])) & 0xffffffff,
                br[1],
                rol(br[2], 10),
                br[3]
            ]
        return bl, br


class RIPEMD_256(RIPEMD_128):
    def __init__(self):
        super(RIPEMD_128, self).__init__()
        # initial values
        self.iv = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
            0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567
        ]

    def compression_func(self, cv, block):
        # buffer
        bl = cv[:4].copy()
        br = cv[4:].copy()
        for i in range(64):
            bl = [
                bl[3],
                rol((bl[0] + r_func[i // 16](bl[1], bl[2], bl[3]) + block[zl[i]] + kl1[i // 16]) & 0xffffffff, sl[i]),
                bl[1],
                bl[2]
            ]
            br = [
                br[3],
                rol((br[0] + r_func[(63 - i) // 16](br[1], br[2], br[3]) + block[zr[i]] + kr1[i // 16]) & 0xffffffff, sr[i]),
                br[1],
                br[2]
            ]
            if i % 16 == 15:
                j = i // 16
                bl[j], br[j] = br[j], bl[j]
        return bl + br

    def hash(self, message_bytes):
        # chaining variables
        cv = self.iv.copy()
        # message blocks
        blocks = self.get_blocks(self.padding(message_bytes))

        for block in blocks:
            buffer = self.compression_func(cv, block)
            # bitwise addition
            for i in range(len(cv)):
                cv[i] = (buffer[i] + cv[i]) & 0xffffffff
        # big-endian output
        for i in range(len(cv)):
            cv[i] = int.from_bytes(cv[i].to_bytes(4, byteorder='little'), byteorder='big')
        # hex format
        return ''.join([hex(h)[2:].zfill(8) for h in cv])


class RIPEMD_320(RIPEMD_256):
    def __init__(self):
        super(RIPEMD_256, self).__init__()
        self.iv = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
            0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f
        ]

    def compression_func(self, cv, block):
        # buffer
        bl = cv[:5].copy()
        br = cv[5:].copy()
        for i in range(80):
            bl = [
                bl[4],
                (bl[4] + rol((bl[0] + r_func[i // 16](bl[1], bl[2], bl[3]) + block[zl[i]] + kl2[i // 16]) & 0xffffffff, sl[i])) & 0xffffffff,
                bl[1],
                rol(bl[2], 10),
                bl[3]
            ]
            br = [
                br[4],
                (br[4] + rol((br[0] + r_func[(79 - i) // 16](br[1], br[2], br[3]) + block[zr[i]] + kr2[i // 16]) & 0xffffffff, sr[i])) & 0xffffffff,
                br[1],
                rol(br[2], 10),
                br[3]
            ]
            if i % 16 == 15:
                j = (((i + 1) // 8) - 1) % 5
                bl[j], br[j] = br[j], bl[j]
        return bl + br
