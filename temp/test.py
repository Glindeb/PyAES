import numpy as np
from AES_Python import AES

aes_test = AES(running_mode="CBC",
               key="2b7e151628aed2a6abf7158809cf4f3c",
               iv="000102030405060708090A0B0C0D0E0F"
               )

print(aes_test, "\n")

data_raw = '6bc1bee22e409f96e93d7e117393172a'

data = "".join([chr(i) for i in bytes.fromhex(data_raw)])

print("Original data:", data)

enc_data = aes_test.enc(data_string=data)

print("Encrypted data:", bytearray([ord(i) for i in enc_data]).hex())

print("Expected:", "7649abac8119b246cee98e9b12e9197d")

dec_data = aes_test.dec(data_string=enc_data)

print("Decrypted data:", dec_data)
