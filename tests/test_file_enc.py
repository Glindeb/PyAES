import os
import pytest
from AES_Python import AES


@pytest.mark.parametrize("data,key,file_name,expected", [
    # 128 bit
    (b'1234567890', "2b7e151628aed2a6abf7158809cf4f3c", "tmp.txt",
     b'|\x94\x18\xcf\x1c\xf0\xef\xa0\xff\xa4\xbb\xe9\xd8\x8am\xa40f\xe4\x1eg\x9d\x88\xb8\xef\xeb{=J\xf3\xf6\xc1'),
    (b'1234567890123456', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt",
     b'(>\xa4JH\xd7\x18\xa2\xc1\xf7\xb7\xe3\xbbKJ\xf8}\xf7k\x0c\x1a\xb8\x99\xb3>B\xf0G\xb9\x1bTo'),
    # 192 bit
    (b'1234567890', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp2.txt",
     b'K\x9d\xe5\xe9l8&\xdalO\xbb\xc3\xf2\xc3*\xf2\xfe\x9a\xbd!U\x9d\xf3\xaa\x8a\xb2\xac\x96@jyU'),
    (b'1234567890123456', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt",
     b'\xf9\x01\xd7\xe8\xdc\xf7\\\xc0\xc8\xa1*>t\xabA\xd8"E-\x8eI\xa8\xa5\x93\x9fs!\xce\xeamQK'),
    # 256 bit
    (b'1234567890', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp4.txt",
     b'2 ?\xebm\xf5o\xc2\x8b\x90\x80\x84 D\xc4\x95\x89\x18\n\xeb\xac\xde\xa7P>Ei\xbc|\x9c\xfa\xf2'),
    (b'1234567890123456', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt",
     b"\x8cc'\xc8d\x82\xb3\x8cj\xd2\\\xaa\x96\xf1\xffi\xe5h\xf6\x81\x94\xcfv\xd6\x17ML\xc0C\x10\xa8T")
])
def test_enc_ecb(data, key, file_name, expected):
    with open(file_name, "wb") as file:
        file.write(data)

    ecb = AES(key=key, running_mode="ECB")
    ecb.enc(file_path=file_name)

    with open(f"{file_name}.enc", "rb") as file:
        result = file.read()

    os.remove(f"{file_name}.enc")

    assert result == expected


@pytest.mark.parametrize("data,key,file_name,iv,expected", [
    # 128 bit
    (b'1234567890', "2b7e151628aed2a6abf7158809cf4f3c", "tmp.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'\xe4\xa7\x0e\xbd\x84\xfa\xf5\xd8`\xb8\xa1\x10\x0b~\xadh\x89Feso\xc5~_|\xe9\x1bG\xd9*\\\x81'),
    (b'1234567890123456', "2b7e151628aed2a6abf7158809cf4f3c", "tmp1.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\r\xd6F?\x82\xd5\x02\x9e\xf6\xc2vJ\xdc\x05\x92\xbc'),
    # 192 bit
    (b'1234567890', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp2.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'\x89\x8fwWh\xaf\xfb@\xc9\xc3\xc0w\x81\xf7\x0e\xd3\xfd\x93\r\x15\x05\xc7\xb5%\xc2k\t\xe8s*\xa7\x9e'),
    (b'1234567890123456', "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "tmp3.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'5\xb9\x19\x1dd\xf3e\xd7EP\x01^8\xb0\xf6\xfb\xc1\x86\xafZ\x0c\x11\x13\x1d4P\x85\x1b"\xdf\x14\xc6'),
    # 256 bit
    (b'1234567890', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp4.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'\x9dT\xb7B\x19e\xb8q\xc95\xfa\x80L\x88.9)`\xef\xc2\x10\x9a\x95\x90U\xe0\x0f N\x80\xba\xb3'),
    (b'1234567890123456', "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "tmp5.txt",
     "000102030405060708090a0b0c0d0e0f",
     b'a\xfdIRQ\xf8\xf1D\xcc\xbf\x89\xc8\xd6\xec\x01;pNAT\xedT\xd9Tp-_\xbbr\xd3\xb5\x11')
])
def test_enc_cbc(data, key, file_name, iv, expected):
    with open(file_name, "wb") as file:
        file.write(data)

    cbc = AES(key=key, running_mode="CBC", iv=iv)
    cbc.enc(file_path=file_name)

    with open(f"{file_name}.enc", "rb") as file:
        result = file.read()

    os.remove(f"{file_name}.enc")

    assert result == expected
