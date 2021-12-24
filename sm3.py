# 32-bit constants
T0 = 0x79cc4519
T1 = 0x7a879d8a

# boolean functions
FF0 = lambda x, y, z: x ^ y ^ z                     #  0 <= j <= 15
FF1 = lambda x, y, z: (x & y) | (x & z) | (y & z)   # 16 <= j <= 63

GG0 = FF0                                           #  0 <= j <= 15
GG1 = lambda x, y, z: (x & y) | (~x & z)            # 16 <= j <= 63

# permutation functions
P0 = lambda x: x ^ rol(x, 9) ^ rol(x, 17)
P1 = lambda x: x ^ rol(x, 15) ^ rol(x, 23)

# Rotate Left (ROL)
rol = lambda w, s: (w >> (32 - s)) | ((w << s) & 0xffffffff)


class SM3:
    def __init__(self):
        # initial values
        self.iv = [
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
        ]

    def get_blocks(self, message_bytes):
        blocks = []
        # divide the message into successive 512-bit blocks
        for i in range(0, len(message_bytes), 64):
            block = []
            for j in range(16):
                block.append(int.from_bytes(message_bytes[i + j * 4: i + j * 4 + 4], 'big'))
            # block expansion
            for j in range(16, 68):
                block.append(P1(block[j - 16] ^ block[j - 9] ^ rol(block[j - 3], 15)) ^ rol(block[j - 13], 7) ^ block[j - 6])
            for j in range(64):
                block.append(block[j] ^ block[j + 4])
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
        for j in range(64):
            T = T0 if j <= 15 else T1
            FF = FF0 if j <= 15 else FF1
            GG = GG0 if j <= 15 else GG1            
            SS1 = rol((rol(b[0], 12) + b[4] + rol(T, j % 32)) & 0xffffffff, 7)
            SS2 = SS1 ^ rol(b[0], 12)
            TT1 = (FF(b[0], b[1], b[2]) + b[3] + SS2 + block[j - 64]) & 0xffffffff
            TT2 = (GG(b[4], b[5], b[6]) + b[7] + SS1 + block[j]) & 0xffffffff
            b = [
                TT1,
                b[0],
                rol(b[1], 9),
                b[2],
                P0(TT2),
                b[4],
                rol(b[5], 19),
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
            # bitwise xor
            for i in range(len(cv)):
                cv[i] = buffer[i] ^ cv[i]
        # hex format
        return ''.join([hex(h)[2:].zfill(8) for h in cv])
