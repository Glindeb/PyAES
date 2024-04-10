import pytest
import os
from AES-Python.decrypt import decrypt

@pytest.mark.parametrize("data,key,file_name,expected", [
    # 128 bit
    (b'|\x94\x18\xcf\x1c\xf0\xef\xa0\xff\xa4\xbb\xe9\xd8\x8am\xa40f\xe4\x1eg\x9d\x88\xb8\xef\xeb{=J\xf3\xf6\xc1', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", b'1234567890'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8}\xf7k\x0c\x1a\xb8\x99\xb3>B\xf0G\xb9\x1bTo', "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", b'1234567890123456'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8\x93\xb1N\xa8\x13I\xd8\xae\xdaw\xee\xef\xdc\xac\xc2\xdb\xf2\x01\xfa.\x10P\x87\xf27Q\xf7\xf5\x86\xb40\xd3', "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", b'12345678901234567890'),
    # 192 bit
    (b'K\x9d\xe5\xe9l8&\xdalO\xbb\xc3\xf2\xc3*\xf2\xfe\x9a\xbd!U\x9d\xf3\xaa\x8a\xb2\xac\x96@jyU', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", b'1234567890'),
    (b'\xf9\x01\xd7\xe8\xdc\xf7\\\xc0\xc8\xa1*>t\xabA\xd8"E-\x8eI\xa8\xa5\x93\x9fs!\xce\xeamQK', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", b'1234567890123456'),
    # 256 bit
    (b'2 ?\xebm\xf5o\xc2\x8b\x90\x80\x84 D\xc4\x95\x89\x18\n\xeb\xac\xde\xa7P>Ei\xbc|\x9c\xfa\xf2', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", b'1234567890'),
    (b"\x8cc'\xc8d\x82\xb3\x8cj\xd2\\\xaa\x96\xf1\xffi\xe5h\xf6\x81\x94\xcfv\xd6\x17ML\xc0C\x10\xa8T", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", b'1234567890123456')
])
def test_aes_decryption_ECB(data, key, file_name, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    decrypt(key, f"{file_name}.enc", "ECB")

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected


@pytest.mark.parametrize("data,key,file_name,iv,expected", [
    # 128 bit
    (b'\xe4\xa7\x0e\xbd\x84\xfa\xf5\xd8`\xb8\xa1\x10\x0b~\xadh\x89Feso\xc5~_|\xe9\x1bG\xd9*\\\x81', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\r\xd6F?\x82\xd5\x02\x9e\xf6\xc2vJ\xdc\x05\x92\xbc', "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee^\x84=\xa1\x00<J\xfc\xdfC#\xf7\x9d\xee~\x7f,\x92ZVX \x1ck\xac\xf2\xd2\xe6\x17u\xa2\xc1', "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", "000102030405060708090a0b0c0d0e0f", b'12345678901234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\x8b\x03\xcc\xe7\x0c~\xba7\xcf\x0f\x9c\x16dM$\xe9\x91\xef\xc3\xa6\xd2\xf0\xcd\xc2\xee\x86\xf0\x90\x8a]\x87\xf5R\xe2.c\xd4\xc6T\xdc\xe0#\xa7X\x8b_\x81\x04', "2b7e151628aed2a6abf7158809cf4f3c", "tmp8.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456789012345678901234567890'),
    # 192 bit
    (b'\x89\x8fwWh\xaf\xfb@\xc9\xc3\xc0w\x81\xf7\x0e\xd3\xfd\x93\r\x15\x05\xc7\xb5%\xc2k\t\xe8s*\xa7\x9e', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'5\xb9\x19\x1dd\xf3e\xd7EP\x01^8\xb0\xf6\xfb\xc1\x86\xafZ\x0c\x11\x13\x1d4P\x85\x1b"\xdf\x14\xc6', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    # 256 bit
    (b'\x9dT\xb7B\x19e\xb8q\xc95\xfa\x80L\x88.9)`\xef\xc2\x10\x9a\x95\x90U\xe0\x0f N\x80\xba\xb3', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'a\xfdIRQ\xf8\xf1D\xcc\xbf\x89\xc8\xd6\xec\x01;pNAT\xedT\xd9Tp-_\xbbr\xd3\xb5\x11', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456')
])
def test_aes_decryption_CBC(data, key, file_name, iv, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    decrypt(key, f"{file_name}.enc", "CBC", iv)

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected


@pytest.mark.parametrize("data,key,file_name,iv,expected", [
    # 128 bit
    (b'\xe4\xa7\x0e\xbd\x84\xfa\xf5\xd8`\xb8\xa1\x10\x0b~\xadhJ\xa98\x9f\xceZ\xd4\x9f"\xde\x00\xf6w\xa9\x1b\x05', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xeeD\xc2\x1d\x19\x93\xd4\x7f\xed\xc8\xb8\xa1\xb60ow\xdd', "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\x0e\xcez\xe5\xcde\x91Q7\xc3|\x8bB\xe6\x96\xc0\x0e%0).\x8006\xf7V\xa1P\xf4\xec\xc0\x05', "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", "000102030405060708090a0b0c0d0e0f", b'12345678901234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xeeg\x19\xcc\xa3\x86K\xfax\xae\n\xee!k\xcc\xcb\xf2:\xfe\xa7,9jJo\xf6/q\xce\xec\x8b\xfd\xee\xc6\xee]\x9f\xbf\xcb~\x84\x8b\xd6\xe6\xed\xba\xbe\xbb.', "2b7e151628aed2a6abf7158809cf4f3c", "tmp8.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456789012345678901234567890'),
    # 192 bit
    (b"\x89\x8fwWh\xaf\xfb@\xc9\xc3\xc0w\x81\xf7\x0e\xd3s\xee\xdf\xa7\xaf\x9f\xddV\x92\x18\x11\r'\xc1\x8d\xfa", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'5\xb9\x19\x1dd\xf3e\xd7EP\x01^8\xb0\xf6\xfb\xe6\xc0\x12\xd1\xfa\x0fr\xde\xc5\xc4\xb9\x9a\xcc\xcd\x9d\xea', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    # 256 bit
    (b'\x9dT\xb7B\x19e\xb8q\xc95\xfa\x80L\x88.9\x97]D\xd8L\xf7\x7f\xc4D\xb3\xbe\xb7\xe1\x81\xe5/', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'a\xfdIRQ\xf8\xf1D\xcc\xbf\x89\xc8\xd6\xec\x01;\xe3\xba\xba{-\xbdz\xa0r\x9c\xd6\xed\x86\xa0\xe2\xee', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456')
])
def test_aes_decryption_PCBC(data, key, file_name, iv, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    decrypt(key, f"{file_name}.enc", "PCBC", iv)

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected


@pytest.mark.parametrize("data,key,file_name,iv,expected", [
    # 128 bit
    (b'a\xccT\xf8\xac[\x05\x8e\xe397\xe9\x9b\xaf\xec`\xd9\xa4\xda\xda\x08\x92#\x9fk\x8b=v\x80\xe1Vr', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'a\xccT\xf8\xac[\x05\x8e\xe39\x06\xdb\xa8\x9b\xd9V\xd9\xa4\xda\xda\x08\x92#\x9fk\x8b=v\x80\xe1Vt', "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    (b'a\xccT\xf8\xac[\x05\x8e\xe39\x06\xdb\xa8\x9b\xd9V\xee\x9c\xe3\xea\x08\x92#\x9fk\x8b=v\x80\xe1Vt\xa7\x88\x19X?\x03\x08\xe7\xa6\xbf6\xb18j\xbf/', "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", "000102030405060708090a0b0c0d0e0f", b'12345678901234567890'),
    (b"a\xccT\xf8\xac[\x05\x8e\xe39\x06\xdb\xa8\x9b\xd9V\xee\x9c\xe3\xea9\xa0\x10\xab^\xbd\nN\xb9\xd1gF\x94\xbc,n\x08;1\xd7\xa6\xbf6\xb18j\xbf#\xc6\xd3Am)\x16\\o\xcb\x8eQ\xa2'\xba\x99F", "2b7e151628aed2a6abf7158809cf4f3c", "tmp8.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456789012345678901234567890'),
    # 192 bit
    (b"\x97;\x80\xb9\xc6\x87$\x05\xe4\xcf'\x18\xba\tV^R\xef\x01\xdaR`/\xe0\x97_x\xac\x84\xbf\x8aV", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'\x97;\x80\xb9\xc6\x87$\x05\xe4\xcf\x16*\x89=chR\xef\x01\xdaR`/\xe0\x97_x\xac\x84\xbf\x8aP', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    # 256 bit
    (b'\x86\x8d\ti\xc1\x0f\xbe\xe5\xae\xc0\xfa\x97\xeb\xce/J\xe1\xc6V0^\xd1\xa7\xa6V8\x05to\xe0>\xda', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'\x86\x8d\ti\xc1\x0f\xbe\xe5\xae\xc0\xcb\xa5\xd8\xfa\x1a|\xe1\xc6V0^\xd1\xa7\xa6V8\x05to\xe0>\xdc', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456')
])
def test_aes_decryption_OFB(data, key, file_name, iv, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    decrypt(key, f"{file_name}.enc", "OFB", iv)

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected
