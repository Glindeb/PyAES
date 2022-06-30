"""
This is a AES-128, AES-192, AES-256 bit encryption algorithm (Rijndael cipher)
implementation in Python 3.10 (no external libraries needed) that can be used
as an external library for AES encryption in python.

OBS!
Please note that this is a purely educational project designed to be used as a
testing, evaluation and learning platform but should still probably provide
a reasonable security when used for encryption and decryption.

"""
# ---------------
# Imports
# ---------------


# ---------------
# Program information m.m
# ---------------
__author__ = 'Gabriel Lindeblad'
__copyright__ = 'Copyright 2022, Circut Labs'
__credits__ = [""]
__license__ = ''
__version__ = '1.0'
__maintainer__ = 'Gabriel Lindeblad'
__email__ = 'Gabriel.lindeblad@icloud.com'
__status__ = 'Development'


# ---------------
# Core data class
# ---------------


class Core_data:
    def __init__(self):
        # For progress bar
        self.progress = 0
        self.total_progress = 0

        # Error count
        self.errors = 0

        # Key variables
        self.key = ''
        self.keysize = 0
        self.key_storage_path = ''
        self.key_storage_mode = 'False'

        # Round info
        self.number_of_rounds = 0
        self.round_keys = ''

        # Running mode
        self.running_mode = ''

        # Sbox & inverse Sbox
        self.subBytesTable = (
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
            )
        self.invSubBytesTable = (
            0x52, 0x09,	0x6a, 0xd5, 0x30, 0x36,	0xa5, 0x38,	0xbf, 0x40,	0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3,	0x39, 0x82, 0x9b, 0x2f,	0xff, 0x87,	0x34, 0x8e,	0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b,	0x94, 0x32, 0xa6, 0xc2,	0x23, 0x3d,	0xee, 0x4c,	0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e,	0xa1, 0x66, 0x28, 0xd9,	0x24, 0xb2,	0x76, 0x5b,	0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8,	0xf6, 0x64, 0x86, 0x68,	0x98, 0x16,	0xd4, 0xa4,	0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70,	0x48, 0x50, 0xfd, 0xed,	0xb9, 0xda,	0x5e, 0x15,	0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8,	0xab, 0x00, 0x8c, 0xbc,	0xd3, 0x0a,	0xf7, 0xe4,	0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c,	0x1e, 0x8f, 0xca, 0x3f,	0x0f, 0x02,	0xc1, 0xaf,	0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91,	0x11, 0x41, 0x4f, 0x67,	0xdc, 0xea,	0x97, 0xf2,	0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac,	0x74, 0x22, 0xe7, 0xad,	0x35, 0x85,	0xe2, 0xf9,	0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1,	0x1a, 0x71, 0x1d, 0x29,	0xc5, 0x89,	0x6f, 0xb7,	0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56,	0x3e, 0x4b, 0xc6, 0xd2,	0x79, 0x20,	0x9a, 0xdb,	0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd,	0xa8, 0x33, 0x88, 0x07,	0xc7, 0x31,	0xb1, 0x12,	0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51,	0x7f, 0xa9, 0x19, 0xb5,	0x4a, 0x0d,	0x2d, 0xe5,	0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0,	0x3b, 0x4d, 0xae, 0x2a,	0xf5, 0xb0,	0xc8, 0xeb,	0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b,	0x04, 0x7e, 0xba, 0x77,	0xd6, 0x26,	0xe1, 0x69,	0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
            )

        # Round constant
        self.round_constant = (
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
            )


# ---------------
# Actions class
# ---------------
class Actions:
    # Progress bar display and update
    def progress_bar(self, progress: int, total_progress: int):
        percent = 100 * (float(progress) / float(total_progress))
        bar = '#' * int(percent) + '-' * (100 - int(percent))
        print(f"\r[{bar}] {percent:.2f}%", end="\r")
        return progress + 16

    # Counts and displays error messages
    def error_message(self, message: str, errors: int):
        print('[Error ' + message + ']')
        return errors + 1

    # Converts a 16-byte array into a 4x4 matrix
    def bytes_to_matrix(self, data: bytearray):
        return [list(data[i:i+4]) for i in range(0, len(data), 4)]

    # Converts a 4x4 matrix into a 16-byte array
    def matrix_to_bytes(self, matrix: list[list[int]]):
        return bytes(sum(matrix, []))

    # Converts a list to a matrix of 4x4
    def list_to_matrix(self, data: list[int]) -> list[list[int]]:
        return [list(data[i:i+4]) for i in range(0, len(data), 4)]

    # Add round key function
    def add_round_key(self, data: list[list[int]], round_key: list[int]):
        key = self.list_to_matrix(round_key)
        for i in range(4):
            for j in range(4):
                self.galois_multiplication(data[i][j], key[i][j])
        return data

    # Performs the byte substitution layer
    def sub_bytes(self, data: list[list[int]], bytesTable: tuple[int]):
        for r in range(4):
            for c in range(4):
                data[r][c] = bytesTable[data[r][c]]
        return data

    # Shift rows function
    def shift_rows(self, data: list[list[int]]):
        data[0][1], data[1][1], data[2][1], data[3][1] = data[1][1], data[2][1], data[3][1], data[0][1]
        data[0][2], data[1][2], data[2][2], data[3][2] = data[2][2], data[3][2], data[0][2], data[1][2]
        data[0][3], data[1][3], data[2][3], data[3][3] = data[3][3], data[0][3], data[1][3], data[2][3]
        return data

    # Inverse shift rows function
    def inv_shift_rows(self, data: list[list[int]]):
        data[0][1], data[1][1], data[2][1], data[3][1] = data[3][1], data[0][1], data[1][1], data[2][1]
        data[0][2], data[1][2], data[2][2], data[3][2] = data[2][2], data[3][2], data[0][2], data[1][2]
        data[0][3], data[1][3], data[2][3], data[3][3] = data[1][3], data[2][3], data[3][3], data[0][3]
        return data

    # Performs the mix columns layer
    def mix_columns(self, data: list[list[int]]):
        for c in range(4):
            a = data[0][c]
            b = data[1][c]
            c = data[2][c]
            d = data[3][c]
            data[0][c] = self.galois_multiplication(a, 2) ^ self.galois_multiplication(b, 3) ^ c ^ d
            data[1][c] = a ^ self.galois_multiplication(b, 2) ^ self.galois_multiplication(c, 3) ^ d
            data[2][c] = a ^ b ^ self.galois_multiplication(c, 2) ^ self.galois_multiplication(d, 3)
            data[3][c] = self.galois_multiplication(a, 3) ^ b ^ c ^ self.galois_multiplication(d, 2)
        return data

    # Galois multiplication function (preforms multiplication in the Galois field)
    def galois_multiplication(self, a: int, b: int):
        p = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set == 0x80:
                a ^= 0x1b
            b >>= 1
        return p & 0xff


# ---------------
# AES main class
# ---------------
class AES(Actions, Core_data):
    def __init__(self):
        super().__init__()

    # Loading Core data
    core_data = Core_data