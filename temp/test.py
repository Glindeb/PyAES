import numpy as np
from AES_Python import AES

aes_test = AES()

print("Key:", aes_test.key)
print("IV:", aes_test.iv)
print("Running mode:", aes_test.running_mode, "\n")

aes_test.key = AES.key_gen()
aes_test.iv = AES.key_gen()
aes_test.running_mode = "CBC"

print("Key:", aes_test.key)
print("IV:", aes_test.iv)
print("Running mode:", aes_test.running_mode)
