from md5 import MD5
from ripemd import RIPEMD_128, RIPEMD_160, RIPEMD_256, RIPEMD_320
from sha1 import SHA_1
from sha2_256 import SHA_2_256
from sha2_512 import SHA_2_512
from sha3 import SHA_3
from sm3 import SM3


if __name__ == '__main__':

    message_list = [
        '',
        'a',
        'abc',
        # 'abcd' * 16,
        # 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        # "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
        # "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        # 'a' * 1000000,
        # '01234567012345670123456701234567' * 20,
        # 'message digest',
        # 'abcdefghijklmnopqrstuvwxyz',
        # 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        # '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
        # 'The quick brown fox jumps over the lazy dog.'
    ]


    md5_encoder = MD5()

    ripemd_128_encoder = RIPEMD_128()
    ripemd_160_encoder = RIPEMD_160()
    ripemd_256_encoder = RIPEMD_256()
    ripemd_320_encoder = RIPEMD_320()

    sha_1_encoder = SHA_1()
    sha_2_256_encoder = SHA_2_256()
    sha_2_512_encoder = SHA_2_512()

    sha_3_224_encoder = SHA_3(output_bits=224)
    sha_3_256_encoder = SHA_3(output_bits=256)
    sha_3_384_encoder = SHA_3(output_bits=384)
    sha_3_512_encoder = SHA_3(output_bits=512)

    sm3_encoder = SM3()


    for message in message_list:
        message_bytes = message.encode(encoding='utf-8')

        md5_code = md5_encoder.hash(message_bytes)

        ripemd_128_code = ripemd_128_encoder.hash(message_bytes)
        ripemd_160_code = ripemd_160_encoder.hash(message_bytes)
        ripemd_256_code = ripemd_256_encoder.hash(message_bytes)
        ripemd_320_code = ripemd_320_encoder.hash(message_bytes)

        sha_1_code = sha_1_encoder.hash(message_bytes)

        sha_2_256_code = sha_2_256_encoder.hash(message_bytes)
        sha_2_512_code = sha_2_512_encoder.hash(message_bytes)

        sha_3_224_code = sha_3_224_encoder.hash(message_bytes)
        sha_3_256_code = sha_3_256_encoder.hash(message_bytes)
        sha_3_384_code = sha_3_384_encoder.hash(message_bytes)
        sha_3_512_code = sha_3_512_encoder.hash(message_bytes)

        sm3_code = sm3_encoder.hash(message_bytes)

        # if message == 'a' * 1000000:
        #     message = "'a' * 1000000"
        # if message == '0123456701234567012345670123456701234567012345670123456701234567' * 10:
        #     message = "'0123456701234567012345670123456701234567012345670123456701234567' * 10"
        
        print(f'Plain Text: {message}')
        
        print(f'MD5 32-bit: {md5_code}')
        print(f'MD5 16-bit: {md5_code[8: 24]}')

        print(f'RIPEMD-128: {ripemd_128_code}')
        print(f'RIPEMD-160: {ripemd_160_code}')
        print(f'RIPEMD-256: {ripemd_256_code}')
        print(f'RIPEMD-320: {ripemd_320_code}')

        print(f'SHA-1:      {sha_1_code}')

        print(f'SHA-2-256:  {sha_2_256_code}')
        print(f'SHA-2-512:  {sha_2_512_code}')

        print(f'SHA-3-224:  {sha_3_224_code}')
        print(f'SHA-3-256:  {sha_3_256_code}')
        print(f'SHA-3-384:  {sha_3_384_code}')
        print(f'SHA-3-512:  {sha_3_512_code}')

        print(f'SM3:        {sm3_code}')

        print()
