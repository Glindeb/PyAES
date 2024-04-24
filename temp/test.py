import numpy as np
from AES_Python import AES

aes_test = AES(key="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")

print(aes_test)

data = '1234567890123456'

enc_data = aes_test.enc(data_string=data)

print("Enc_data:", enc_data)
print("Bytes_data:", bytes(enc_data, "utf-8"))  # type:ignore

dec_data = aes_test.dec(data_string=enc_data)   # type: ignore

print(dec_data)