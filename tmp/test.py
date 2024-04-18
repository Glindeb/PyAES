import numpy as np
from numpy.typing import NDArray
import sys
sys.path.append('../')
from src.AES import AES


A = "6bc1bee22e409f96e93d7e117393172a"

print(A)

B = np.frombuffer(bytes.fromhex(A), dtype=np.uint8).reshape(4, 4)

print(B)

print(B.astype(np.int8).tobytes().hex())

C = np.array([[2, 3, 1, 1],  # Matrix used for shift columns operation
                                         [1, 2, 3, 1],
                                         [1, 1, 2, 3],
                                         [3, 1, 1, 2]])

print(C)
C.transpose()
print(C)