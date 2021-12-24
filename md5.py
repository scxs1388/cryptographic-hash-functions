import math

# 32-bit constants
k = tuple([int((1 << 32) * abs(math.sin(i + 1))) & 0xffffffff for i in range(64)])
# k = (
#     0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
#     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
#     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
#     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
#     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
#     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
#     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
#     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
# )

# left rotation offsets
s = (
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
)

# selections of message words
m = (
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
	5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
	0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
)

# non-linear boolean functions
r_func = [
    lambda x, y, z: (x & y) | (~x & z),     #  0 <= i <= 15
    lambda x, y, z: (x & z) | (y & ~z),     # 16 <= i <= 31
    lambda x, y, z: x ^ y ^ z,              # 32 <= i <= 47
    lambda x, y, z: y ^ (x | ~z)            # 48 <= i <= 63
]

# Rotate Left (ROL)
rol = lambda w, s: (w >> (32 - s)) | ((w << s) & 0xffffffff)


class MD5:
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
        b = cv.copy()
        for i in range(64):
            # single step
            # b = [
            #     b[3],
            #     (b[1] + rol(b[0] + r_func[i // 16](b[1], b[2], b[3]) + block[m[i]] + k[i], s[i])) & 0xffffffff,
            #     b[1],
            #     b[2],
            # ]

            # 4 successive steps
            j = i % 4
            b[-j] = (b[1 - j] + rol((b[-j] + r_func[i // 16](b[1 - j], b[2 - j], b[3 - j]) + block[m[i]] + k[i]) & 0xffffffff, s[i])) & 0xffffffff
        return b

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
