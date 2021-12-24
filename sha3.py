import numpy as np

# Keccak constants 
l_list = [0, 1, 2, 3, 4, 5, 6]
w_list = [2 ** l for l in l_list]
b_list = [25 * w for w in w_list]

# rho function bitshift offsets
shifts = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14]
]

# iota function round constants
RCs = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]


class SHA_3:
    def __init__(self, output_bits):
        # lane width
        self.w = w_list[6]
        # SHA-3 b = 1600
        self.b = b_list[6]
        # capacity
        self.c = output_bits * 2
        # rate
        self.r = self.b - self.c
        # number of rounds
        self.nr = 24
        # output hash code bits
        self.output_bits = output_bits

    def message2bitstring(self, message_bytes):
        bitstring = ''
        for byte in message_bytes:
            # little endian
            bitstring += '{0:08b}'.format(byte)[::-1]
        # bitstring += '01100000' # 0x06
        return bitstring

    def bitstring2array(self, bitstring):
        # convert a bitstring into an (5, 5, w=64) array
        array = np.zeros([5, 5, self.w], dtype=int)
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    if (self.w * (5 * x + y) + z) < len(bitstring):
                        array[y][x][z] = int(bitstring[self.w * (5 * x + y) + z])
        return array

    def hexnum2array(self, hexnum):
        # Convert a hexstring to a 1-dimensional numpy array
        bitstring = '{0:064b}'.format(hexnum)
        bitstring = bitstring[-self.w:]
        array = np.array([int(bitstring[i]) for i in range(self.w)])
        return array

    # SHA-3 Appendix B.2 Hexadecimal Padding
    def padding(self, message_length):
        if self.r - message_length == 8:
            return '01100001'
        j = (-message_length - 9) % self.r
        return '01100000' + '0' * j + '1'

    # 1. θ function
    def theta(self, array):
        # For each column, XOR the parity of two adjacent columns
        array_prime = array.copy()
        C, D = np.zeros([5, self.w], dtype=int), np.zeros([5, self.w], dtype=int)
        for x in range(5):
            for y in range(5):
                C[x] ^= array[x][y] # C[x] is a lane, each entry represents the column parity
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ np.roll(C[(x + 1) % 5], 1) # D[x] is a placeholder
        for x in range(5):
            for y in range(5):
                array_prime[x][y] ^= D[x] # For each lane, XOR the value of D[x]
        return array_prime
    
    # 2. ρ function
    def rho(self, array):
        # Circular shift each lane by a precalculated amount (given by the shifts array)
        array_prime = array.copy()
        for x in range(5):
            for y in range(5):
                array_prime[x][y] = np.roll(array[x][y], shifts[x][y])
        return array_prime

    # 3. π function
    def pi(self, array):
        # 'Rotate' each slice according to a modular linear transformation
        array_prime = array.copy()
        for x in range(5):
            for y in range(5):
                array_prime[x][y] = array[((x) + (3 * y)) % 5][x]
        return array_prime

    # 4. χ function
    def chi(self, array):
        # Bitwise transformation of each row according to a nonlinear function
        array_prime = np.zeros(array.shape, dtype=int)
        for x in range(5):
            for y in range(5):
                array_prime[x][y] = array[x][y] ^ ((array[(x + 1) % 5][y] ^ 1) & (array[(x + 2) % 5][y]))
        return array_prime

    # 5. ι function
    def iota(self, array, ir):
        # XOR each lane with a precalculated round constant
        RC = np.flip(self.hexnum2array(RCs[ir]))
        array_prime = array.copy()
        array_prime[0][0] ^= RC
        return array_prime

    # keccak-p[1600, 24]
    def keccak(self, state_array):
        for ir in range(self.nr):
            state_array = self.iota(self.chi(self.pi(self.rho(self.theta(state_array)))), ir)
        return state_array

    # absorb function
    def absorb(self, padded_bitstring):
        # sponge absorb rounds
        n = len(padded_bitstring) // self.r
        # initial state array (5, 5, w=64) s0
        state_array = np.zeros(self.b, dtype=int).reshape(5, 5, self.w)
        for i in range(n):
            bitstring = padded_bitstring[i * self.r: i * self.r + self.r]
            p_array = self.bitstring2array(bitstring)
            state_array = self.keccak(np.bitwise_xor(state_array, p_array))
        return state_array

    # squeeze function (r > d)
    def squeeze(self, state_array):
        hash_code = ''
        for x in range(5):
            for y in range(5):
                lane = state_array[y][x]
                lane_bitstring = ''
                for z in range(len(lane)):
                    lane_bitstring += str(lane[z])
                for n in range(0, len(lane_bitstring), 8):
                    byte = lane_bitstring[n: n + 8]
                    byte = byte[::-1]
                    hash_code += '{0:02x}'.format(int(byte, 2))
        return hash_code[:int(self.output_bits / 4)]

    def sponge(self, padded_bitstring):
        # absorbing
        state_array = self.absorb(padded_bitstring)
        # squeezing
        hash_code = self.squeeze(state_array)
        return hash_code

    def hash(self, message_bytes):
        bitstring = self.message2bitstring(message_bytes)
        # padding
        padded_bitstring = bitstring + self.padding(len(bitstring) % self.r)
        return self.sponge(padded_bitstring)
