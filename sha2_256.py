prime = (
      2,   3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,
     59,  61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107, 109, 113, 127, 131,
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
)

# 32-bit constants
k = tuple([int((p ** (1 / 3)) * (1 << 32)) & 0xffffffff for p in prime])
# k = (
#     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
#     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
#     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
#     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
#     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
#     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
#     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
#     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
# )

# Shift Logical Right (SHR)
shr = lambda w, s: (w & 0xffffffff) >> s
# Rotate Right (ROR)
ror = lambda w, s: (w >> s) | ((w << (32 - s)) & 0xffffffff)
# choose
ch = lambda x, y, z: (x & y) ^ (~x & z)
# majority
maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)
# sigma0
sig0 = lambda x: ror(x, 7) ^ ror(x, 18) ^ shr(x, 3)
# sigma1
sig1 = lambda x: ror(x, 17) ^ ror(x, 19) ^ shr(x, 10)
# SIGMA0
SIG0 = lambda x: ror(x, 2) ^ ror(x, 13) ^ ror(x, 22)
# SIGMA1
SIG1 = lambda x: ror(x, 6) ^ ror(x, 11) ^ ror(x, 25)


class SHA_2_256:
    def __init__(self):
        # initial values
        self.iv = [int((prime[i] ** (1 / 2)) * (1 << 32)) & 0xffffffff for i in range(8)]
        # self.iv = [
        #     0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        #     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        # ]

    def get_blocks(self, message_bytes):
        blocks = []
        # divide the message into successive 512-bit blocks
        for i in range(0, len(message_bytes), 64):
            block = []
            for j in range(16):
                block.append(int.from_bytes(message_bytes[i + j * 4: i + j * 4 + 4], 'big'))
            # block expansion
            for j in range(16, 64):
                block.append((block[j - 16] + sig0(block[j - 15]) + block[j - 7] + sig1(block[j - 2])) & 0xffffffff)
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
        for i in range(64):
            T1 = b[7] + ch(b[4], b[5], b[6]) + block[i] + k[i] + SIG1(b[4])
            T2 = maj(b[0], b[1], b[2]) + SIG0(b[0])
            b = [
                (T1 + T2) & 0xffffffff,
                b[0],
                b[1],
                b[2],
                (b[3] + T1) & 0xffffffff,
                b[4],
                b[5],
                b[6]
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
