import os
import pytest
from AES_Python import AES


@pytest.mark.skip(reason="Not correctly implemented yet")
@pytest.mark.parametrize("data,key,file_name,expected", [
    # 128 bit
    (b'|\x94\x18\xcf\x1c\xf0\xef\xa0\xff\xa4\xbb\xe9\xd8\x8am\xa40f\xe4\x1eg\x9d\x88\xb8\xef\xeb{=J\xf3\xf6\xc1',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", b'1234567890'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8}\xf7k\x0c\x1a\xb8\x99\xb3>B\xf0G\xb9\x1bTo',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", b'1234567890123456'),
    (b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8\x93\xb1N\xa8\x13I\xd8\xae\xdaw\xee\xef\xdc\xac\xc2\xdb\xf2\x01\xfa.\x10P\x87\xf27Q\xf7\xf5\x86\xb40\xd3',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", b'12345678901234567890'),
    # 192 bit
    (b'K\x9d\xe5\xe9l8&\xdalO\xbb\xc3\xf2\xc3*\xf2\xfe\x9a\xbd!U\x9d\xf3\xaa\x8a\xb2\xac\x96@jyU',
     "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", b'1234567890'),
    (b'\xf9\x01\xd7\xe8\xdc\xf7\\\xc0\xc8\xa1*>t\xabA\xd8"E-\x8eI\xa8\xa5\x93\x9fs!\xce\xeamQK',
     "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", b'1234567890123456'),
    # 256 bit
    (b'2 ?\xebm\xf5o\xc2\x8b\x90\x80\x84 D\xc4\x95\x89\x18\n\xeb\xac\xde\xa7P>Ei\xbc|\x9c\xfa\xf2',
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", b'1234567890'),
    (b"\x8cc'\xc8d\x82\xb3\x8cj\xd2\\\xaa\x96\xf1\xffi\xe5h\xf6\x81\x94\xcfv\xd6\x17ML\xc0C\x10\xa8T",
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", b'1234567890123456')
])
def test_file_dec_ecb(data, key, file_name, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    ecb = AES(key=key, running_mode="ECB")
    ecb.dec(file_path=file_name)

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected


@pytest.mark.skip(reason="Not correctly implemented yet")
@pytest.mark.parametrize("data,key,file_name,iv,expected", [
    # 128 bit
    (b'\xe4\xa7\x0e\xbd\x84\xfa\xf5\xd8`\xb8\xa1\x10\x0b~\xadh\x89Feso\xc5~_|\xe9\x1bG\xd9*\\\x81',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\r\xd6F?\x82\xd5\x02\x9e\xf6\xc2vJ\xdc\x05\x92\xbc',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp2.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee^\x84=\xa1\x00<J\xfc\xdfC#\xf7\x9d\xee~\x7f,\x92ZVX \x1ck\xac\xf2\xd2\xe6\x17u\xa2\xc1',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp7.txt", "000102030405060708090a0b0c0d0e0f", b'12345678901234567890'),
    (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\x8b\x03\xcc\xe7\x0c~\xba7\xcf\x0f\x9c\x16dM$\xe9\x91\xef\xc3\xa6\xd2\xf0\xcd\xc2\xee\x86\xf0\x90\x8a]\x87\xf5R\xe2.c\xd4\xc6T\xdc\xe0#\xa7X\x8b_\x81\x04',
     "2b7e151628aed2a6abf7158809cf4f3c", "tmp8.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456789012345678901234567890'),
    # 192 bit
    (b'\x89\x8fwWh\xaf\xfb@\xc9\xc3\xc0w\x81\xf7\x0e\xd3\xfd\x93\r\x15\x05\xc7\xb5%\xc2k\t\xe8s*\xa7\x9e',
     "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'5\xb9\x19\x1dd\xf3e\xd7EP\x01^8\xb0\xf6\xfb\xc1\x86\xafZ\x0c\x11\x13\x1d4P\x85\x1b"\xdf\x14\xc6',
     "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp4.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456'),
    # 256 bit
    (b'\x9dT\xb7B\x19e\xb8q\xc95\xfa\x80L\x88.9)`\xef\xc2\x10\x9a\x95\x90U\xe0\x0f N\x80\xba\xb3',
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890'),
    (b'a\xfdIRQ\xf8\xf1D\xcc\xbf\x89\xc8\xd6\xec\x01;pNAT\xedT\xd9Tp-_\xbbr\xd3\xb5\x11',
     "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp6.txt", "000102030405060708090a0b0c0d0e0f", b'1234567890123456')
])
def test_file_dec_cbc(data, key, file_name, iv, expected):
    with open(f"{file_name}.enc", "wb") as file:
        file.write(data)

    cbc = AES(key=key, running_mode="CBC")
    cbc.dec(file_path=file_name)

    with open(file_name, "rb") as file:
        result = file.read()

    os.remove(file_name)

    assert result == expected
