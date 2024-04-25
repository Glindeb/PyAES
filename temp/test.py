import numpy as np
from AES_Python import AES

aes_test = AES(key="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")

print(aes_test, "\n")

data = '1234567890123456'

print("Original data:", data)

enc_data = aes_test.enc(data_string=data)

print("Encrypted data:", enc_data)

dec_data = aes_test.dec(data_string=enc_data)

print("Decrypted data:", dec_data)
