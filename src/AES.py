"""This is a simple AES (Advanced Encryption Standard) implementation in Python 3.12. It is
a pure Python implementation of AES that is designed to be used as an educational tool
only. It is not intended to be used in any other use case than educational and no
security is guaranteed for data encrypted or decrypted using this tool."""

# Imports
import numpy as np
from numpy.typing import NDArray
from secrets import token_bytes
from os.path import getsize
from os import remove


class AES:
    """
    AES class...
    """

    # Substitution box
    sub_box: tuple[int, ...] = (
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

    # Inverse substitution box
    inv_sub_box: tuple[int, ...] = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    # Round constants
    r_const: tuple[int, ...] = (
        0x00000000, 0x01000000, 0x02000000,
        0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000,
        0x1B000000, 0x36000000, 0x6C000000,
        0xD8000000, 0xAB000000, 0x4D000000,
    )

    def __init__(self, r_mode: str, version: int, *, key: bytes = b'') -> None:
        """
        Initialization of AES object.
        :param r_mode: Specify running mode. (ECB, CBC, OFB, PCBC...)
        :param version: Specify AES encryption version. (128, 256, 512)
        :param key: Key used for encryption. If not specified generates random key.
        :return: None
        """
        if key:
            self.key: bytes = key
        else:
            self.key = self.key_gen(version // 8)

        self.r_mode = r_mode

        raise NotImplementedError

    def enc(self) -> bytes:
        raise NotImplementedError

    def dec(self) -> bytes:
        raise NotImplementedError

    def enc_file(self) -> None:
        raise NotImplementedError

    def dec_file(self) -> None:
        raise NotImplementedError

    @staticmethod
    def key_gen(length: int = 16) -> bytes:
        """ Generates a random byte sequence of specified length using secrets library.
        :param length: Length of byte sequence (number of bytes).
        :returns: Byte sequence.
        """
        return token_bytes(length)

    def key_expand(self, key: bytes = b'') -> NDArray[np.int8]:
        if not key:
            key = self.key

        # Format key correctly for the key expansion
        key_array: NDArray[np.int8] = np.frombuffer(key, dtype=np.uint8)

        # Key expansion setup
        # This part determines the number of rounds and the number of words
        # using the key length.
        if len(key) == 16:
            words = self.__key_schedule(key, 4, 11)
            nr = 11
        if len(key) == 24:
            words = self.__key_schedule(key, 6, 13)
            nr = 13
        if len(key) == 32:
            words = self.__key_schedule(key, 8, 15)
            nr = 15

        # Create list for storing the round keys & tmp list for storing
        # for temporary storage.
        round_keys = [None for i in range(nr)]
        tmp = [None for i in range(4)]

        # Formats the words to a list of tuples
        for i in range(nr * 4):
            for index, t in enumerate(words[i]):
                tmp[index] = int(t, 16)  # type: ignore
            words[i] = tuple(tmp)

        # Formats teh words to a list of numpy arrays where each
        # array is a 4x4 matrix representing a round key.
        for i in range(nr):
            round_keys[i] = np.array(words[i * 4] + words[i * 4 + 1] + words[i * 4 + 2] + words[i * 4 + 3]).reshape(4, 4)

        # Returns the list of round keys and the number of rounds
        return round_keys

    # Key schedule (nk = number of colums, nr = number of rounds)
    # This function is used to expand the key to the correct number of round
    @staticmethod
    def __key_schedule(key, nk, nr):
        # Create list for storing the words and populates the first
        # 4 with the specified key.
        words = [(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]) for i in range(nk)]

        # Fill out the rest based on previews four words using the fucnitons, rotword,
        # subword and rcon values
        limit = False
        for i in range(nk, (nr * nk)):
            # Get required previous keywords
            temp, word = words[i - 1], words[i - nk]

            # If multiple of nk use rot, sub, rcon etc
            if i % nk == 0:
                x = SubWord(RotWord(temp))
                rcon = round_constant[int(i / nk)]
                temp = hexor(x, hex(rcon)[2:])
                limit = False
            elif i % 4 == 0:
                limit = True

            if i % 4 == 0 and limit and nk >= 8:
                temp = SubWord(temp)

            # Xor the two hex values
            xord = hexor(''.join(word), ''.join(temp))
            # Add to list
            words.append((xord[:2], xord[2:4], xord[4:6], xord[6:8]))
        # Return the list of words
        return words

    # Takes two hex values and calculates hex1 xor hex2
    def __hexor(hex1, hex2):
        # Convert to binary
        bin1 = hex2binary(hex1)
        bin2 = hex2binary(hex2)

        # Calculate
        xord = int(bin1, 2) ^ int(bin2, 2)

        # Cut prefix
        hexed = hex(xord)[2:]

        # Leading 0s get cut above, if not length 8 add a leading 0
        if len(hexed) != 8:
            hexed = '0' + hexed

        # Return hex
        return hexed

    # Takes a hex value and returns binary
    def __hex2binary(hex):
        return bin(int(str(hex), 16))

    # Takes from 1 to the end, adds on from the start to 1
    def __RotWord(word):
        return word[1:] + word[:1]

    # Selects correct values from sbox based on the current word
    # and replaces the word with the new values.
    def __SubWord(word):
        # Create list for storing the new word
        sWord = []

        # Loop through the current word
        for i in range(4):

            # Check first char, if its a letter(a-f) get corresponding decimal
            # otherwise just take the value and add 1
            if word[i][0].isdigit() is False:
                row = ord(word[i][0]) - 86
            else:
                row = int(word[i][0]) + 1

            # Repeat above for the seoncd char
            if word[i][1].isdigit() is False:
                col = ord(word[i][1]) - 86
            else:
                col = int(word[i][1]) + 1

            # Get the index base on row and col (16x16 grid)
            sBoxIndex = (row * 16) - (17 - col)

            # Get the value from sbox and removes prefix (0x)
            piece = hex(subBytesTable[sBoxIndex])[2:]

            # Check length to ensure leading 0s are not forgotton
            if len(piece) != 2:
                piece = '0' + piece

            # Adds the new value to the list
            sWord.append(piece)

        # Returning word as string
        return ''.join(sWord)

    # Xtime
    # Used to preform multiplication by x in the Galois field
    def __xtime(a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    # Byte substitution function
    # Substitutes each byte in the state with a byte from the S-Box
    def __sub_bytes(data, bytes_table):
        for i, row in enumerate(data):
            for j, byte in enumerate(row):
                data[i][j] = bytes_table[byte]
        return data

    # Shift rows function
    # Shifts the rows of the matrix to the left.
    # Each row is shifted by the number of its index
    def __shift_rows(array):
        array[:, 1] = np.roll(array[:, 1], -1, axis=0)
        array[:, 2] = np.roll(array[:, 2], -2, axis=0)
        array[:, 3] = np.roll(array[:, 3], -3, axis=0)
        return array

    # Inverse shift rows function
    # Shifts the rows of the matrix to the right.
    # Each row is shifted by the number of its index
    def __inv_shift_rows(array):
        array[:, 1] = np.roll(array[:, 1], 1, axis=0)
        array[:, 2] = np.roll(array[:, 2], 2, axis=0)
        array[:, 3] = np.roll(array[:, 3], 3, axis=0)
        return array

    # Performs the mix columns layer
    def __mix_columns(data):
        # mixes a single column
        def mix_single_column(data):
            t = data[0] ^ data[1] ^ data[2] ^ data[3]
            u = data[0]
            data[0] ^= t ^ xtime(data[0] ^ data[1])
            data[1] ^= t ^ xtime(data[1] ^ data[2])
            data[2] ^= t ^ xtime(data[2] ^ data[3])
            data[3] ^= t ^ xtime(data[3] ^ u)

        # mixes all columns using mix_single_column
        def mix(data):
            for i in range(4):
                mix_single_column(data[i])
            return data

        data = mix(data)
        return data

    # Preforms the inverse mix columns layer
    # This function is similar to the mix_columns function
    # but instead preforms the inverse operation.
    def __inv_mix_columns(data):
        for i in range(4):
            u = xtime(xtime(data[i][0] ^ data[i][2]))
            v = xtime(xtime(data[i][1] ^ data[i][3]))
            data[i][0] ^= u
            data[i][1] ^= v
            data[i][2] ^= u
            data[i][3] ^= v
        mix_columns(data)
        return data

    # Adds a padding to ensure a bloke size of 16 bytes
    def __add_padding(data):
        length = 16 - len(data)
        for i in range(length):
            data.append(0)
        return data, length

    # Removes the padding from the data
    def __remove_padding(data, identifier):
        if identifier[-1] == 0:
            return data
        elif identifier[-1] > 0 and identifier[-1] < 16:
            return data[:-identifier[-1]]
        else:
            raise ValueError('Invalid padding')
