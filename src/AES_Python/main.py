"""
This is a simple AES (Advanced Encryption Standard) implementation in Python 3.12. This
implementation is designed to be used as an educational tool only. It is not intended to
be used in any other use case than educational and no security is guaranteed for data
encrypted or decrypted using this tool.
"""
import os

# Imported libraries
import numpy as np  # Used for arrays and mathematical operations.
import galois  # Used for GF(2^8) multiplication in mix columns operation.
from numpy.typing import NDArray  # Used for type hinting numpy arrays.
from typing import Any  # Used for type hinting __getattr__ function.
from secrets import token_bytes  # Used for generating random key if needed.
from os.path import getsize  # Used to acquire size of files.
from os import remove  # Used to remove files.


class AES:
    """
    The AES class implements the Advanced Encryption Standard (AES) algorithm for symmetric key cryptography.
    It supports different modes of operation (ECB, CBC) and key lengths (128, 256, 512 bits).

    Attributes:
        version (str): The version of the encryption, either 128, 192 or 256 bit.
        _running_mode (str): The running mode for AES. Default is "ECB".
        _key (str): The encryption key. If not provided, a random key is generated.
        _iv (str): The initialization vector used for "CBC" encryption.

    Methods:
        get: Retrieves the value of specified attribute.
        set: Changes the value of specified attribute.
        enc: Encrypts either a string of unspecified length or a file.
        dec: Decrypts string or file.
        key_gen: Generates a random byte string of specified length (16, 24 or 32 bytes) in hexadecimal.
        key_expand: Expands the given key to 11, 13 or 15 round keys depending on key length.
    """

    # Substitution box
    SUB_BOX: NDArray[np.uint8] = np.array([
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

    # Inverse substitution box
    INV_SUB_BOX: NDArray[np.uint8] = np.array([
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
    ])

    # Vectorize built-in chr() function
    vec_chr = np.vectorize(chr)

    def __init__(self, *, running_mode: str = "ECB", version: str = "128", key: str = "", iv: str = "") -> None:
        """
        Initialization of AES object.
        :param running_mode: Specify running mode. (ECB or CBC)
        :param version: Specify AES encryption version. (128, 256, 512)
        :param key: Key used for encryption. If not specified generates random key.
        :param iv: Initialization vector used during CBC running mode.
        :return: None.
        """
        if key:
            self._key: str = key
        else:
            self._key = str(self.key_gen(int(version) // 8))  # Generates key if missing

        if iv:
            self._iv = iv
        else:
            self._iv = str(self.key_gen())  # Generates iv if missing

        self._running_mode: str = running_mode

    def __repr__(self) -> str:
        """
        Returns string with information about running_mode, key and iv of object.
        :return: Information string.
        """
        return (f"Object <{type(self).__name__}>. \n"
                f" - Running mode = '{self._running_mode}' \n"
                f" - Key = '{self._key}' \n"
                f" - IV = '{self._iv}' ")

    def set(self, attr: str, value: str) -> None:
        """
        Preforms check of attribute and new value before allowing assignment.
        :param attr: Attribute to be changed. Valid attributes (running_mode, key, iv).
        :param value: New attribute value.
        :return: None.
        """
        if attr == "key":
            if isinstance(value, str) and ((len(value) / 2) in [16, 24, 32]):
                self.__dict__[f"_{attr}"] = value
            else:
                raise TypeError("Unsupported key length, supported types are (16, 24, 32) bytes.")
        elif attr == "iv":
            if isinstance(value, str) and ((len(value) / 2) == 16):
                self.__dict__[f"_{attr}"] = value
            else:
                raise TypeError("Unsupported iv length, supported length is 16 bytes.")
        elif attr == "running_mode":
            if isinstance(value, str) and value in ["ECB", "CBC"]:
                self.__dict__[f"_{attr}"] = value
            else:
                raise TypeError("Unsupported running mode, supported modes are ECB, CBC.")
        else:
            raise AttributeError(f"No changeable attribute <{attr}> exists!")

    def get(self, item: str) -> Any:
        """
        Preforms check before retrieving attribute.
        :param item: Attribute to be retrieved. Valid attributes (running_mode, key, iv).
        :return: Attribute value.
        """
        if item in ["running_mode", "key", "iv"]:
            return self.__dict__[f"_{item}"]
        else:
            raise AttributeError(f"No attribute <{item}> exists!")

    def enc(self, *, data_string: str = "", file_path: str = "",
            running_mode: str = "", key: str = "", iv: str = "") -> str:
        """
        Encrypts either a string or a file using selected running_mode, key and iv.
        :param data_string: Data string to be encrypted.
        :param file_path: Path to file that is encrypted.
        :param running_mode: Running mode used for encryption.
        :param key: Key used for encryption.
        :param iv: Initialization vector used for CBC encryption.
        :return: Data string or writes encrypted file.
        """
        if not running_mode:
            running_mode = self._running_mode
        else:
            self.set("running_mode", running_mode)

        if not key:
            key = self._key
        else:
            self.set("key", key)

        if not iv:
            iv = self._iv
        else:
            self.set("iv", iv)

        if data_string:
            if running_mode == "ECB":
                return self.__ecb_enc(data_string=data_string, keys=self.key_expand(key))
            elif running_mode == "CBC":
                return self.__cbc_enc(data_string=data_string, keys=self.key_expand(key), iv=iv)
            else:
                raise NotImplementedError(f"{running_mode} is not supported!")
        elif file_path:
            if running_mode == "ECB":
                self.__ecb_enc(file_path=file_path, keys=self.key_expand(key))
                return ""
            elif running_mode == "CBC":
                self.__cbc_enc(file_path=file_path, keys=self.key_expand(key), iv=iv)
                return ""
            else:
                raise NotImplementedError(f"{running_mode} is not supported!")
        else:
            raise RuntimeWarning("No file or string was give...")

    def dec(self, *, data_string: str = "", file_path: str = "",
            running_mode: str = "", key: str = "", iv: str = "") -> str:
        """
        Decrypts either a string or a file using selected running_mode, key and iv.
        :param data_string: Data string to be decrypted.
        :param file_path: Path to file that is decrypted.
        :param running_mode: Running mode used for decryption.
        :param key: Key used for decryption.
        :param iv: Initialization vector used for CBC decryption.
        :return: Data string or writes decrypted file.
        """
        if not running_mode:
            running_mode = self._running_mode
        else:
            self.set("running_mode", running_mode)

        if not key:
            key = self._key
        else:
            self.set("key", key)

        if not iv:
            iv = self._iv
        else:
            self.set("iv", iv)

        if data_string:
            if running_mode == "ECB":
                return self.__ecb_dec(data_string=data_string, keys=self.key_expand(key))
            elif running_mode == "CBC":
                return self.__cbc_dec(data_string=data_string, keys=self.key_expand(key), iv=iv)
            else:
                raise NotImplementedError(f"{running_mode} is not supported!")
        elif file_path:
            if running_mode == "ECB":
                self.__ecb_dec(file_path=file_path, keys=self.key_expand(key))
                return ""
            elif running_mode == "CBC":
                self.__cbc_dec(file_path=file_path, keys=self.key_expand(key), iv=iv)
                return ""
            else:
                raise NotImplementedError(f"{running_mode} is not supported!")
        else:
            raise RuntimeWarning("No file or string was give...")

    @classmethod
    def __ecb_enc(cls, *, data_string: str = "", file_path: str = "", keys: NDArray[np.uint8]) -> str:
        """
        Preforms ECB encryption instructions on specified file or data string.
        :param data_string: Data string to be encrypted.
        :param file_path: Path to file that is encrypted.
        :param keys: Key used for encryption.
        :return: Data string or writes encrypted file.
        """
        if data_string:
            output_string: str = ""

            for i in range(len(data_string) // 16):  # Encryption cycle, skips last if not integer multiple of 16 bytes
                raw: NDArray[np.uint8] = np.array([ord(i) for i in data_string[(i * 16): ((i + 1) * 16)]],
                                                  dtype=np.uint8).reshape(4, 4)

                enc: str = "".join(cls.vec_chr(cls.__enc_schedule(raw, keys).flatten().astype(np.uint8)))
                output_string += enc

            extra = len(data_string) % 16  # Calculates length of final data block
            result: str = ""

            if extra != 0:  # If last data block not integer multiple of 16 adds extra padding
                raw = np.full(16, 0, dtype=np.uint8)
                raw[:extra] = np.array([ord(i) for i in data_string][-1 * extra:], dtype=np.uint8)

                result = "".join(cls.vec_chr(cls.__enc_schedule(raw.reshape(4, 4), keys).flatten().astype(np.uint8)))

            return output_string + result
        elif file_path:
            file_size = getsize(file_path)

            with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
                for i in range(int(file_size / 16)):
                    raw = np.array([i for i in data.read(16)], dtype=np.uint8).reshape(4, 4)
                    out = bytes((cls.__enc_schedule(raw, keys).flatten()).tolist())
                    output.write(out)

                if file_size % 16 != 0:
                    raw_l = [i for i in data.read()]
                    raw_l, length = cls.__add_padding(raw_l)

                    out = bytes((cls.__enc_schedule(np.array(raw_l).reshape(4, 4), keys).flatten()).tolist())
                    identifier = bytes((cls.__enc_schedule(np.array([0 for i in range(15)] + [length]).reshape(4, 4),
                                                           keys).flatten()).tolist())

                    output.write(out + identifier)
                else:
                    identifier = bytes((cls.__enc_schedule(np.array([0 for i in range(16)]).reshape(4, 4),
                                                           keys).flatten()).tolist())
                    output.write(identifier)

            remove(file_path)
            return ""
        else:
            raise RuntimeError("No string or file path received...?")

    @classmethod
    def __ecb_dec(cls, *, data_string: str = "", file_path: str = "", keys: NDArray[np.uint8]) -> str:
        """
        Preforms ECB decryption instructions on specified file or data string.
        :param data_string: Data string to be decrypted.
        :param file_path: Path to file that is decrypted.
        :param keys: Key used for decryption.
        :return: Data string or writes decrypted file.
        """
        if data_string:
            output_string: str = ""

            for i in range(len(data_string) // 16):  # Decryption cycle
                raw: NDArray[np.uint8] = np.array(
                    [ord(i) for i in data_string[(i * 16): ((i + 1) * 16)]], dtype=np.uint8).reshape(4, 4)

                dec: str = "".join(cls.vec_chr(cls.__dec_schedule(raw, keys).flatten().astype(np.uint8)))

                output_string += dec

            return output_string
        elif file_path:
            file_size = getsize(file_path)
            file_name = file_path[:-4]

            with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
                for i in range(int(file_size / 16) - 2):
                    raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                    result = bytes((cls.__dec_schedule(raw, keys).flatten()).tolist())
                    output.write(result)

                data_final = np.array([i for i in data.read(16)]).reshape(4, 4)
                identifier = np.array([i for i in data.read()]).reshape(4, 4)

                data_dec = (cls.__dec_schedule(data_final, keys).flatten()).tolist()
                id_l = (cls.__dec_schedule(identifier, keys).flatten()).tolist()

                result = bytes(cls.__remove_padding(data_dec, id_l))

                output.write(result)

            remove(file_path)
            return ""
        else:
            raise RuntimeError("No string or file path received...?")

    @classmethod
    def __cbc_enc(cls, *, data_string: str = "", file_path: str = "", keys: NDArray[np.uint8], iv: str) -> str:
        """
        Preforms CBC encryption instructions on specified file or data string.
        :param data_string: Data string to be encrypted.
        :param file_path: Path to file that is encrypted.
        :param keys: Key used for encryption.
        :param iv: Initialization vector used.
        :return: Data string or writes encrypted file.
        """
        enc_array: NDArray[np.uint8] = np.frombuffer(bytes.fromhex(iv), dtype=np.uint8).reshape(4, 4)

        if data_string:
            output_string: str = ""

            for i in range(len(data_string) // 16):  # Encryption cycle, skips last if not integer multiple of 16 bytes
                raw: NDArray[np.uint8] = np.array([ord(i) for i in data_string[(i * 16): ((i + 1) * 16)]],
                                                  dtype=np.uint8).reshape(4, 4)
                enc = np.bitwise_xor(raw, enc_array)  # Xor operation with previous encrypted block or iv
                enc_array = cls.__enc_schedule(enc, keys)
                output_string += "".join(cls.vec_chr(enc_array.flatten().astype(np.uint8)))

            extra = len(data_string) % 16  # Calculates length of final data block
            result: str = ""

            if extra != 0:  # If last data block not integer multiple of 16 adds extra padding
                raw = np.full(16, 0, dtype=np.uint8)
                raw[:extra] = np.array([ord(i) for i in data_string][-1 * extra:], dtype=np.uint8)
                raw = raw.reshape(4, 4)

                temp_array = np.bitwise_xor(raw, enc_array)  # Xor operation with previous encrypted block

                result = "".join(cls.vec_chr(cls.__enc_schedule(temp_array, keys).flatten().astype(np.uint8)))

            return output_string + result
        elif file_path:
            file_size = getsize(file_path)

            with open(f"{file_path}.enc", 'wb') as output, open(file_path, 'rb') as data:
                for i in range(int(file_size / 16)):
                    raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                    raw = np.bitwise_xor(raw, enc_array)
                    enc_array = cls.__enc_schedule(raw, keys)
                    output.write(bytes((enc_array.flatten()).tolist()))

                if file_size % 16 != 0:
                    final = [i for i in data.read()]
                    final, length = cls.__add_padding(final)

                    raw = np.bitwise_xor(np.array(final).reshape(4, 4), enc_array)
                    enc_array = cls.__enc_schedule(raw, keys)

                    identifier = np.bitwise_xor(np.array([0 for i in range(15)] + [length]).reshape(4, 4), enc_array)
                    identifier = cls.__enc_schedule(identifier, keys)

                    output.write(bytes((enc_array.flatten()).tolist() + (identifier.flatten()).tolist()))
                else:
                    identifier = np.bitwise_xor(np.array([0 for i in range(16)]).reshape(4, 4), enc_array)
                    id_bytes = bytes(((cls.__enc_schedule(identifier, keys)).flatten()).tolist())
                    output.write(id_bytes)
            remove(file_path)
            return ""
        else:
            raise RuntimeError("No string or file path received...?")

    @classmethod
    def __cbc_dec(cls, *, data_string: str = "", file_path: str = "", keys: NDArray[np.uint8], iv: str) -> str:
        """
        Preforms CBC decryption instructions on specified file or data string.
        :param data_string: Data string to be decrypted.
        :param file_path: Path to file that is decrypted.
        :param keys: Key used for decryption.
        :param iv: Initialization vector used.
        :return: Data string or writes decrypted file.
        """
        dec_array: NDArray[np.uint8] = np.frombuffer(bytes.fromhex(iv), dtype=np.uint8).reshape(4, 4)

        if data_string:
            output_string: str = ""

            for i in range(len(data_string) // 16):  # Decryption cycle
                raw: NDArray[np.uint8] = np.array(  # Reads in input string 16 bytes at a time
                    [ord(i) for i in data_string[(i * 16): ((i + 1) * 16)]], dtype=np.uint8).reshape(4, 4)

                temp_array = cls.__dec_schedule(raw, keys)
                result = np.bitwise_xor(temp_array, dec_array)
                dec_array = raw

                dec = "".join(cls.vec_chr(result.flatten().astype(np.uint8)))
                output_string += dec

            return output_string
        elif file_path:
            file_size = getsize(file_path)
            file_name = file_path[:-4]

            with open(f"{file_name}", 'wb') as output, open(file_path, 'rb') as data:
                if int(file_size / 16) - 3 >= 0:
                    vector = np.array([i for i in data.read(16)]).reshape(4, 4)
                    raw = cls.__dec_schedule(vector, keys)
                    result = np.bitwise_xor(raw, dec_array)
                    output.write(bytes((result.flatten()).tolist()))

                    for i in range(int(file_size / 16) - 3):
                        raw = np.array([i for i in data.read(16)]).reshape(4, 4)
                        result = cls.__dec_schedule(raw, keys)
                        result = np.bitwise_xor(result, vector)
                        vector = raw
                        output.write(bytes((result.flatten()).tolist()))
                else:
                    vector = dec_array

                data_pice = np.array([i for i in data.read(16)]).reshape(4, 4)
                vector_1, identifier = data_pice, np.array([i for i in data.read()]).reshape(4, 4)

                result = cls.__dec_schedule(data_pice, keys)
                identifier = cls.__dec_schedule(identifier, keys)

                identifier = np.bitwise_xor(identifier, vector_1)
                data_pice = np.bitwise_xor(result, vector)

                result_bytes = bytes(cls.__remove_padding((data_pice.flatten()).tolist(),
                                                          (identifier.flatten()).tolist()))

                output.write(result_bytes)

            remove(file_path)
            return ""
        else:
            raise RuntimeError("No string or file path received...?")

    @staticmethod
    def key_gen(length: int = 16) -> str:
        """ Generates a random byte string of specified length using secrets library.
        :param length: Length of byte sequence (number of bytes).
        :returns: Byte sequence string.
        """
        return token_bytes(length).hex()

    @classmethod
    def __enc_schedule(cls, data: NDArray[np.uint8], r_keys: NDArray[np.uint8]) -> NDArray[np.uint8]:
        """
        Preforms encryption rounds depending on number of round keys.
        :param data: Matrix that is passed through each operation.
        :param r_keys: Matrix containing round keys.
        :return: Encrypted matrix.
        """
        nr: int = len(r_keys)

        # Initial add round key
        data = np.bitwise_xor(data, r_keys[0])

        # Rounds 1 to 9 or 1 to 11 or 1 to 13
        for i in range(1, (nr - 1)):
            data = cls.SUB_BOX[data]  # Sub bytes
            data = cls.__shift_rows(data, -1)  # Shift rows
            data = cls.__mix_columns(data, -1)  # Mix columns
            data = np.bitwise_xor(data, r_keys[i])  # Add round key

        # Final round, identical to the previous rounds but without mix columns step
        data = cls.SUB_BOX[data]
        data = cls.__shift_rows(data, -1)
        data = np.bitwise_xor(data, r_keys[-1])

        # Returns the encrypted data
        return data

    @classmethod
    def __dec_schedule(cls, data: NDArray[np.uint8], r_keys: NDArray[np.uint8]) -> NDArray[np.uint8]:
        """
        Preforms decryption rounds depending on number of round keys.
        :param data: Matrix that is passed through each operation.
        :param r_keys: Matrix containing round keys.
        :return: Decrypted matrix.
        """
        nr: int = len(r_keys)

        # Initial operations (The reverse from final operations in enc_schedule)
        data = np.bitwise_xor(data, r_keys[-1])
        data = cls.__shift_rows(data, 1)
        data = cls.INV_SUB_BOX[data]

        for i in range(2, nr):
            data = np.bitwise_xor(data, r_keys[-i])  # Inverse add round key
            data = cls.__mix_columns(data, 1)  # Inverse mix columns
            data = cls.__shift_rows(data, 1)  # Inverse shift rows
            data = cls.INV_SUB_BOX[data]  # Inverse sub bytes

        # Final round (Identical to first operation in enc_schedule)
        data = np.bitwise_xor(data, r_keys[0])

        return data

    @classmethod
    def key_expand(cls, key: str) -> NDArray[np.uint8]:
        """
        Expands the given key to 11, 13 or 15 round key depending on key length.
        :param key: Key that is expanded.
        :return: Tuple containing round key matrices.
        """

        # Format key correctly for the key expansion
        key_array: NDArray[np.uint8] = np.frombuffer(bytes.fromhex(key), dtype=np.uint8)

        # Key expansion setup:
        # Determines the number of rounds and the number of words using the key length.
        if len(key_array) == 16:
            nr, nc = 11, 4
            round_keys: NDArray[np.uint8] = cls.__key_schedule(key_array, nr, nc)
        elif len(key_array) == 24:
            nr, nc = 13, 6
            round_keys = cls.__key_schedule(key_array, nr, nc)
        elif len(key_array) == 32:
            nr, nc = 15, 8
            round_keys = cls.__key_schedule(key_array, nr, nc)
        else:
            raise ValueError("Unsupported key length...")

        # Returns the list of round keys
        return round_keys

    @classmethod
    def __key_schedule(cls, key: NDArray[np.uint8], nr: int, nc: int) -> NDArray[np.uint8]:
        """
        Key schedule (nc = number of columns, nr = number of rounds).
        This function is used to expand the key to the correct number of round.
        :param key: String bytes in hex format.
        :param nr: Number of encryption rounds.
        :param nc: Number of initial.
        :return: NDArray.
        """
        # Round constants
        rcon: NDArray[np.uint8] = np.array([[0x00, 0x00, 0x00, 0x00],
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
                                            ], dtype=np.uint8)

        # Setup list of matrices to store the words
        words: NDArray[np.uint8] = np.full((nr * 4, 4), 0, dtype=np.uint8)

        # Populating first words with key
        words[0:nc] = np.array_split(key, nc)

        # Generates the rest of the words
        for i in range(nc, (4 * nr)):
            if i % nc == 0:
                words[i] = words[i - 1]  # Moves working word to next word
                words[i] = np.roll(words[i], -1)  # RotWord
                words[i] = cls.SUB_BOX[words[i]]  # SubWord
                words[i] = np.bitwise_xor(words[i], rcon[i // nc])  # Round constant xor
                words[i] = np.bitwise_xor(words[i], words[i - nc])  # Xor with i - nc word
            elif (i % 4) == 0 and nc == 8:
                words[i] = cls.SUB_BOX[words[i - 1]]  # SubWord using previous word
                words[i] = np.bitwise_xor(words[i], words[i - nc])  # Xor with i - nc word
            else:
                words[i] = np.bitwise_xor(words[i - 1], words[i - nc])  # Xor previous word with i - nc word

        # Return the list of words
        return words.reshape(nr, 4, 4)

    @staticmethod
    def __shift_rows(matrix: NDArray[np.uint8], shift: int) -> NDArray[np.uint8]:
        """
        Shifts the rows of the matrix to the left. Each row is shifted by the number of its index.
        :param matrix: NDArray to preform row shifting on.
        :param shift: Integer of either -1 or 1 depending on direction of operation. (-1: Normal, 1: inverse)
        :return: NDArray.
        """
        matrix = matrix.transpose()  # Fix due to this implementations use rows and columns
        matrix[1, :] = np.roll(matrix[1, :], shift * 1)
        matrix[2, :] = np.roll(matrix[2, :], shift * 2)
        matrix[3, :] = np.roll(matrix[3, :], shift * 3)
        return matrix.transpose()

    @staticmethod
    def __mix_columns(matrix: NDArray[np.uint8], shift: int) -> NDArray[np.uint8]:
        """
        Preforms the shift columns (or inverse shift columns) operation on the input matrix.
        :param matrix: NDArray to preform shift columns on.
        :param shift: Integer of either -1 or 1 depending on direction of operation. (-1: Normal, 1: inverse)
        :return: NDArray.
        """
        matrix = matrix.transpose()  # Fix for this implementations way of handling columns and rows

        # Initializing AES GF(2^8) object for finite field multiplication
        gf = galois.GF(2 ** 8, irreducible_poly=0x11b)

        cx: NDArray[np.uint8] = np.array([[2, 3, 1, 1],  # Matrix used for shift columns operation
                                          [1, 2, 3, 1],
                                          [1, 1, 2, 3],
                                          [3, 1, 1, 2]], dtype=np.uint8)
        dx: NDArray[np.uint8] = np.array([[14, 11, 13, 9],  # Matrix used for inverse shift columns operation
                                          [9, 14, 11, 13],
                                          [13, 9, 14, 11],
                                          [11, 13, 9, 14]], dtype=np.uint8)

        # Determines if preforming inverse operation or not
        if shift < 0:
            table = cx
        else:
            table = dx

        # Preforms Galois multiplication with each column separately
        result = np.zeros_like(matrix)
        for i in range(4):
            for j in range(4):
                temp: NDArray[np.uint8] = gf(table[j, 0]) * gf(matrix[0, i])
                for k in range(1, 4):
                    temp ^= gf(table[j, k]) * gf(matrix[k, i])  # type: ignore
                result[j, i] = temp

        return result.transpose()

    @staticmethod
    def __add_padding(data: list[int]) -> tuple[list[int], int]:
        """Adds a padding to ensure a bloke size of 16 bytes."""
        length = 16 - len(data)
        for i in range(length):
            data.append(0)
        return data, length

    @staticmethod
    def __remove_padding(data: list[int], identifier: list[int]) -> list[int]:
        """Removes the padding from the data using information from identifier."""
        if identifier[-1] == 0:
            return data
        elif 0 < identifier[-1] < 16:
            return data[:-identifier[-1]]
        else:
            raise ValueError('Invalid padding')
