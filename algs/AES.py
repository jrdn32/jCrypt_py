import numpy as np

# circularly shifts bits in a given word by n_bits
def rot_word(word, n_bits):
    return (word << n_bits) | (word >> (32 - n_bits)) & 0xFFFFFFFF

# apply AES sbox to each byte of the word
def sub_word(word):
    sub1_index = (word >> 24) & 0xFF
    sub2_index = (word >> 16) & 0xFF
    sub3_index = (word >> 8)  & 0xFF
    sub4_index = word & 0xFF
    sub1 = sbox[sub1_index >> 4][sub1_index & 0xF] << 24
    sub2 = sbox[sub2_index >> 4][sub2_index & 0xF] << 16
    sub3 = sbox[sub3_index >> 4][sub3_index & 0xF] << 8
    sub4 = sbox[sub4_index >> 4][sub4_index & 0xF]

    return sub1 + sub2 + sub3 + sub4

# the AES key expansion algorithm
def gen_key_schedule(K, K_bitlen) -> np.array:
    N = K_bitlen//32                    # number of 32-bit words in key
    R = 7 + N                             # number of round keys needed
    W = np.empty((4*R), dtype=np.uint32)  # the round keys partitioned into 32-bit words
    round_keys = np.empty((R, 4), dtype=object)
    key_mask = 0xFFFFFFFF

    # apply the key expansion algorithm
    for i in range(0, 4*R):
        if (i < N):                           W[i] = K[i]
        elif (i >= N and i%N == 0):           W[i] = W[i-N] ^ sub_word(rot_word(W[i-1], 8)) ^ rcon[i//N - 1]
        elif (i >= N and N > 6 and i%N == 4): W[i] = W[i-N] ^ sub_word(W[i-1])
        else:                                 W[i] = W[i-N] ^ W[i-1]

        round_keys[i//4][i%4] = W[i]

    return round_keys



"""
The following functions implement the various transformation steps taken in a single AES
encryption round. For encryption, the order of the transformations is: substitude bytes,
shift rows, mix columns, and add round key. For decryption, the order of the transformations
is: inverse shift rows, inverse substitude bytes, add round key, and inverse mix columns.

The final round of both encryption and decryption do not include a mix columns transformation.
"""

def sub_bytes(state):
    for i in range(4): state[i] = sub_word(state[i])

    return state

# each row of bytes is left circularly shifted by 1 byte
# state is a 1-dimensional array where each element is a 32-bit word representing a state column
def shift_rows(state):
    mask = 0xFF000000
    shifted_state = np.zeros(shape=(4), dtype=np.uint32)

    for i in range(len(state)):
        shifted_state[0] ^= state[(i+0)%4] & mask
        shifted_state[1] ^= state[(i+1)%4] & mask
        shifted_state[2] ^= state[(i+2)%4] & mask
        shifted_state[3] ^= state[(i+3)%4] & mask

        mask >>= 8

    return shifted_state


def mul_hex(x, y) -> np.uint32:
    if (y == 0x01): return x
    if (y == 0x02): return (x << 1) if not(x & 0x80) else (((x << 1) & 0xFF) ^ 0x1B)
    if (y == 0x03): return x ^ mul_hex(x, 0x02)
    # the following lines for y greater than 0x03 still need to be fixed and implemented:
    # tmp = (x << 1) if not(x & 0x80) else (((x << 1) & 0xFF) ^ 0x1B)
    # return (tmp ^ mul_hex(tmp, y//2)) if (y % 2) else mul_hex(tmp, y//2)


def mix_single_column(column):
    mixed_column = 0x00000000
    mask = 0x000000FF
    mix_array = np.array([[0x02,0x03,0x01,0x01],
                          [0x01,0x02,0x03,0x01],
                          [0x01,0x01,0x02,0x03],
                          [0x03,0x01,0x01,0x02]])

    for row in range(4):
        tmp = column
        mixed_column <<= 8
        for col in range(4):
            mixed_column ^= mul_hex(tmp & mask, mix_array[row][3 - col])
            tmp >>= 8

    return mixed_column


def mix_columns(state):
    mixed_state = np.empty(shape=(4), dtype=np.uint32)

    for i in range(len(state)):
        mixed_state[i] = mix_single_column(state[i])
        
    return mixed_state


def add_round_key(state, round_key):
    for i in range(4): state[i] ^= round_key[i]

    return state


# perform a single AES encryption round
def encrypt_round(state, round_keys):
    return add_round_key(mix_columns(shift_rows(sub_bytes(state))), round_keys)


# Perform AES encryption for one block of plaintext
# The plaintext block is a 1-dimensional array of hex values, where
# each row represents the state column.
# K is an array where each row is a 32-bit word of the AES key
def encrypt_block(plaintext, round_keys):
    # add initial round key
    state = add_round_key(plaintext, round_keys[0])

    # perform round encryptions
    for i in range(1, len(round_keys) - 1):
        state = encrypt_round(state, round_keys[i])

    # perform last round encryption (no mix columns)
    state = add_round_key(shift_rows(sub_bytes(state)), round_keys[len(round_keys) - 1])

    # return the resulting ciphertext, stored in the current state
    return state


# receives plaintext as an ASCII string
def add_padding(plain, type="IEC"):
    plaintext = plain
    
    if (type == "PKCS7"):
        padding_bytes = 16 - len(plaintext) % 16
        for i in range(padding_bytes):
            plaintext += chr(padding_bytes)
    # ANSI x.923
    elif (type == "ANSI"):
        padding_bytes = 16 - len(plaintext) % 16
        for i in range(padding_bytes - 1):
            plaintext += chr(0x0)
        plaintext += chr(padding_bytes)
    # ISO/IEC 7816
    elif (type == "IEC"):
        for i in range(16 - len(plaintext)%16):
            if (i == 0): plaintext += chr(0x80)
            else:        plaintext += chr(0x00)
    else:
        raise("padding type not supported")

    return plaintext


# Converts a string of ASCII characters into a state-like array
# of 32-bit hexadecimal words
def convert_to_hex_words(text):
    words = np.zeros(shape=(len(text)//4), dtype=np.uint32)

    for i in range(len(words)):
        for j in range(4):
            words[i] <<= 8
            words[i] ^= ord(text[i*4 + j])

    return words


def convert_hex_words_to_ASCII(words):
    text = ""
    tmp = np.copy(words)

    for i in range(len(words)):
        for j in range(4):
            text += chr((tmp[i] & 0xFF000000) >> 24)
            tmp[i] <<= 8

    return text


# Performs AES Electronic Code Book (ECB) encryption
def encrypt_ECB(plain_words, K):
    cipher_words = np.array([], dtype=np.uint32) # Store the resulting encrypted information in 32-bit words
    round_keys = gen_key_schedule(K, len(K)*32)

    # Encrypt each plaintext block
    for i in range(len(plain_words)//4):
        cipher_words = np.append(cipher_words, encrypt_block(plain_words[i*4:(i+1)*4], round_keys))

    return cipher_words


def encrypt_CBC(plain_words, K, IV):
    if (IV == None): raise("Please supply an Initialisation Vector (IV) for CBC encryption mode")
    
    cipher_words = np.array([], dtype=np.uint32) # Store the resulting encrypted information in 32-bit words
    round_keys = gen_key_schedule(K, len(K)*32)
    
    IV_words = convert_to_hex_words(IV)
    block_in = np.copy(plain_words[0:4])

    # XOR IV with plaintext
    for i in range(len(block_in)):
        block_in[i] ^= IV_words[i]
            
    # Perform CBC encryption
    for i in range(0, len(plain_words)//4 - 1):
        cipher_words = np.append(cipher_words, encrypt_block(block_in, round_keys))

        # XOR previous encryption block's output with the input plaintext block
        for j in range(4):
            block_in[j] = plain_words[(i+1)*4 + j] ^ cipher_words[i*4 + j]

    # Encrypt final block
    cipher_words = np.append(cipher_words, encrypt_block(block_in, round_keys))

    return cipher_words
        
    

# Perform AES encryption on a given string
# Both plaintext and sym_key should be ASCII strings
def encrypt(plaintext, sym_key, encrypt_method="ECB", IV = None, pad_method="IEC"):
    # Add padding to plaintext
    padded = add_padding(plaintext, pad_method)

    # Convert plaintext to 32-bit words
    plain_words = convert_to_hex_words(padded)

    # Convert key to 32-bit words
    K = convert_to_hex_words(sym_key)

    # Begin encryption
    if (encrypt_method == "ECB"):
        cipher_words = encrypt_ECB(plain_words, K)

    elif (encrypt_method == "CBC"):
        cipher_words = encrypt_CBC(plain_words, K, IV)

    # Convert cipher_words to ASCII ciphertext
    ciphertext = convert_hex_words_to_ASCII(cipher_words)

    return ciphertext


sbox     = np.array([[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
                     [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
                     [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
                     [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
                     [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
                     [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
                     [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
                     [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
                     [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
                     [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
                     [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
                     [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
                     [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
                     [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
                     [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
                     [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
                    )

inv_sbox = np.array([[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
                     [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
                     [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
                     [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
                     [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
                     [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
                     [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
                     [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
                     [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
                     [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
                     [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
                     [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
                     [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
                     [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
                     [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
                     [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
                    )

rcon     = np.array([0x01000000,   # rcon_1
                     0x02000000,   # rcon_2
                     0x04000000,   # rcon_3
                     0x08000000,   # rcon_4
                     0x10000000,   # rcon_5
                     0x20000000,   # rcon_6
                     0x40000000,   # rcon_7
                     0x80000000,   # rcon_8
                     0x1B000000,   # rcon_9
                     0x36000000]   # rcon_10
                    )
