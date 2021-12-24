# 32-bit constants
k = tuple([int((n ** (1 / 2)) * (1 << 30)) for n in [2, 3, 5, 10]])
# k = (0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6)

# non-linear boolean functions
r_func = [
    lambda x, y, z: (x & y) | (~x & z),             #  0 <= i <= 19
    lambda x, y, z: x ^ y ^ z,                      # 20 <= i <= 39
    lambda x, y, z: (x & y) | (x & z) | (y & z),    # 40 <= i <= 59
    lambda x, y, z: x ^ y ^ z                       # 60 <= i <= 79
]

# Rotate Left (ROL)
rol = lambda w, s: (w >> (32 - s)) | ((w << s) & 0xffffffff)


class SHA_1:
    def __init__(self):
        # initial values
        self.iv = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    def get_blocks(self, message_bytes):
        blocks = []
        # divide the message into successive 512-bit blocks
        for i in range(0, len(message_bytes), 64):
            block = []
            for j in range(16):
                block.append(int.from_bytes(message_bytes[i + j * 4: i + j * 4 + 4], 'big'))
            # block expansion
            for j in range(16, 80):
                block.append(rol(block[j - 16] ^ block[j - 14] ^ block[j - 8] ^ block[j - 3], 1))
            blocks.append(block)
        return blocks

    def padding(self, message_bytes):
        # original message length
        message_byte_length = len(message_bytes)
        # append padding bits until message byte length ≡ 56 mod 64
        message_bytes += b'\x80' + b'\x00' * ((55 - message_byte_length) % 64)
        # append original message length (big-endian)
        message_bytes += (message_byte_length * 8).to_bytes(8, byteorder='big')
        return message_bytes

    def compression_func(self, cv, block):
        # buffer
        b = cv.copy()
        for i in range(80):
            b = [
                (b[4] + r_func[i // 20](b[1], b[2], b[3]) + rol(b[0], 5) + block[i] + k[i // 20]) & 0xffffffff,
                b[0],
                rol(b[1], 30),
                b[2],
                b[3]
            ]
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
        # hex format
        return ''.join([hex(h)[2:].zfill(8) for h in cv])
