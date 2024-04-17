import numpy as np
from numpy.typing import NDArray
import sys
sys.path.append('../')
from src.AES import AES

A: str = "3ad77bb40d7a3660a89ecaf32466ef97"


def numpy_to_string(p):
    return p.tobytes().hex()


print(A)

Q = np.frombuffer(bytes.fromhex(A), dtype=np.uint8)

print(Q)

C = Q.tobytes().hex()

print(C)

obj = AES()

print(dir(obj))