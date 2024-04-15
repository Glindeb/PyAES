import numpy as np
from numpy.typing import NDArray

SUB_BOX: NDArray[np.int8] = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
])

RCON: NDArray[np.int8] = np.array([[0x00, 0x00, 0x00, 0x00],
                                   [0x01, 0x00, 0x00, 0x00],
                                   [0x02, 0x00, 0x00, 0x00],
                                   [0x04, 0x00, 0x00, 0x00],
                                   [0x08, 0x00, 0x00, 0x00],
                                   [0x10, 0x00, 0x00, 0x00],
                                   [0x20, 0x00, 0x00, 0x00],
                                   [0x40, 0x00, 0x00, 0x00],
                                   [0x80, 0x00, 0x00, 0x00],
                                   [0x1B, 0x00, 0x00, 0x00],
                                   [0x36, 0x00, 0x00, 0x00],
                                   [0x6c, 0x00, 0x00, 0x00],
                                   [0xd8, 0x00, 0x00, 0x00],
                                   [0xab, 0x00, 0x00, 0x00],
                                   [0x4d, 0x00, 0x00, 0x00],
                                   [0x9a, 0x00, 0x00, 0x00],
                                   ], dtype=int)


def key_expand(key: str = '') -> NDArray[np.int8]:
    """
    Expands the given key to 11, 13 or 15 round key depending on key length.
    :param key: Key that is expanded.
    :return: Tuple containing round key matrices.
    """

    # Format key correctly for the key expansion
    key_array: NDArray[np.int8] = np.frombuffer(bytes.fromhex(key), dtype=np.int8)

    # Key expansion setup:
    # Determines the number of rounds and the number of words using the key length.
    if len(key_array) == 16:
        nr, nc = 11, 4
        round_keys: NDArray[np.int8] = key_schedule(key_array, nr, nc)
    elif len(key_array) == 24:
        nr, nc = 13, 6
        round_keys = key_schedule(key_array, nr, nc)
    elif len(key_array) == 32:
        nr, nc = 15, 8
        round_keys = key_schedule(key_array, nr, nc)
    else:
        raise ValueError("Unsupported key length...")

    # Returns the list of round keys
    return round_keys


# Key schedule (nc = number of columns, nr = number of rounds)
# This function is used to expand the key to the correct number of round
def key_schedule(key: NDArray[np.int8], nr: int, nc: int) -> NDArray[np.int8]:
    # Setup list of matrices to store the words
    words: NDArray[np.int8] = np.full((nr*4, 4), 0, dtype=int)

    # Populating first words with key
    words[0:nc] = np.array_split(key, nc)

    # Generates the rest of the words
    for i in range(nc, (4 * nr)):
        if i % nc == 0:
            words[i] = words[i - 1]                                 # Moves working word to next word
            words[i] = np.roll(words[i], -1)                        # RotWord
            words[i] = SUB_BOX[words[i]]                            # SubWord
            words[i] = np.bitwise_xor(words[i], RCON[i//nc])        # Round constant xor
            words[i] = np.bitwise_xor(words[i], words[i - nc])      # Xor with i - nc word
        elif (i % 4) == 0 and nc == 8:
            words[i] = SUB_BOX[words[i - 1]]                        # SubWord using previous word
            words[i] = np.bitwise_xor(words[i], words[i - nc])      # Xor with i - nc word
        else:
            words[i] = np.bitwise_xor(words[i - 1], words[i - nc])  # Xor previous word with i - nc word

    # Return the list of words
    return words.reshape(nr, 4, 4)


def test_aes_key_expansion_128bit():
    round_keys = key_expand("00000000000000000000000000000000")

    assert np.array_equal(round_keys, np.array([
        [[0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0]],
        [[98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99]],
        [[155, 152, 152, 201],
         [249, 251, 251, 170],
         [155, 152, 152, 201],
         [249, 251, 251, 170]],
        [[144, 151, 52, 80],
         [105, 108, 207, 250],
         [242, 244, 87, 51],
         [11, 15, 172, 153]],
        [[238, 6, 218, 123],
         [135, 106, 21, 129],
         [117, 158, 66, 178],
         [126, 145, 238, 43]],
        [[127, 46, 43, 136],
         [248, 68, 62, 9],
         [141, 218, 124, 187],
         [243, 75, 146, 144]],
        [[236, 97, 75, 133],
         [20, 37, 117, 140],
         [153, 255, 9, 55],
         [106, 180, 155, 167]],
        [[33, 117, 23, 135],
         [53, 80, 98, 11],
         [172, 175, 107, 60],
         [198, 27, 240, 155]],
        [[14, 249, 3, 51],
         [59, 169, 97, 56],
         [151, 6, 10, 4],
         [81, 29, 250, 159]],
        [[177, 212, 216, 226],
         [138, 125, 185, 218],
         [29, 123, 179, 222],
         [76, 102, 73, 65]],
        [[180, 239, 91, 203],
         [62, 146, 226, 17],
         [35, 233, 81, 207],
         [111, 143, 24, 142]],
    ]))


def test_aes_key_expansion_192bit():
    round_keys = key_expand("000000000000000000000000000000000000000000000000")

    assert np.array_equal(round_keys, np.array([
        [[0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0]],
        [[0, 0, 0, 0],
         [0, 0, 0, 0],
         [98, 99, 99, 99],
         [98, 99, 99, 99]],
        [[98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99]],
        [[155, 152, 152, 201],
         [249, 251, 251, 170],
         [155, 152, 152, 201],
         [249, 251, 251, 170]],
        [[155, 152, 152, 201],
         [249, 251, 251, 170],
         [144, 151, 52, 80],
         [105, 108, 207, 250]],
        [[242, 244, 87, 51],
         [11, 15, 172, 153],
         [144, 151, 52, 80],
         [105, 108, 207, 250]],
        [[200, 29, 25, 169],
         [161, 113, 214, 83],
         [83, 133, 129, 96],
         [88, 138, 45, 249]],
        [[200, 29, 25, 169],
         [161, 113, 214, 83],
         [123, 235, 244, 155],
         [218, 154, 34, 200]],
        [[137, 31, 163, 168],
         [209, 149, 142, 81],
         [25, 136, 151, 248],
         [184, 249, 65, 171]],
        [[194, 104, 150, 247],
         [24, 242, 180, 63],
         [145, 237, 23, 151],
         [64, 120, 153, 198]],
        [[89, 240, 14, 62],
         [225, 9, 79, 149],
         [131, 236, 188, 15],
         [155, 30, 8, 48]],
        [[10, 243, 31, 167],
         [74, 139, 134, 97],
         [19, 123, 136, 95],
         [242, 114, 199, 202]],
        [[67, 42, 200, 134],
         [216, 52, 192, 182],
         [210, 199, 223, 17],
         [152, 76, 89, 112]],
    ]))


def test_aes_key_expansion_256bit():
    round_keys = key_expand("0000000000000000000000000000000000000000000000000000000000000000")

    assert np.array_equal(round_keys, np.array([
        [[0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0]],
        [[0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0],
         [0, 0, 0, 0]],
        [[98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99],
         [98, 99, 99, 99]],
        [[170, 251, 251, 251],
         [170, 251, 251, 251],
         [170, 251, 251, 251],
         [170, 251, 251, 251]],
        [[111, 108, 108, 207],
         [13, 15, 15, 172],
         [111, 108, 108, 207],
         [13, 15, 15, 172]],
        [[125, 141, 141, 106],
         [215, 118, 118, 145],
         [125, 141, 141, 106],
         [215, 118, 118, 145]],
        [[83, 84, 237, 193],
         [94, 91, 226, 109],
         [49, 55, 142, 162],
         [60, 56, 129, 14]],
        [[150, 138, 129, 193],
         [65, 252, 247, 80],
         [60, 113, 122, 58],
         [235, 7, 12, 171]],
        [[158, 170, 143, 40],
         [192, 241, 109, 69],
         [241, 198, 227, 231],
         [205, 254, 98, 233]],
        [[43, 49, 43, 223],
         [106, 205, 220, 143],
         [86, 188, 166, 181],
         [189, 187, 170, 30]],
        [[100, 6, 253, 82],
         [164, 247, 144, 23],
         [85, 49, 115, 240],
         [152, 207, 17, 25]],
        [[109, 187, 169, 11],
         [7, 118, 117, 132],
         [81, 202, 211, 49],
         [236, 113, 121, 47]],
        [[231, 176, 232, 156],
         [67, 71, 120, 139],
         [22, 118, 11, 123],
         [142, 185, 26, 98]],
        [[116, 237, 11, 161],
         [115, 155, 126, 37],
         [34, 81, 173, 20],
         [206, 32, 212, 59]],
        [[16, 248, 10, 23],
         [83, 191, 114, 156],
         [69, 201, 121, 231],
         [203, 112, 99, 133]],
    ]))

