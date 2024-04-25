import numpy as np
from AES_Python import AES

aes_test = AES(running_mode="CBC")

print(aes_test, "\n")

data = 'En lång text med en massa tecken som behöver hantaeras separat och kräver flera rundor'

print("Original data:", data)

enc_data = aes_test.enc(data_string=data)

print("Encrypted data:", enc_data)

dec_data = aes_test.dec(data_string=enc_data)

print("Decrypted data:", dec_data)
