import numpy as np
from numpy.typing import NDArray
import sys
sys.path.append('../')
from src.AES import AES
import galois

GF = galois.GF(2**8, irreducible_poly=0x11b)


A = np.array([[219, 242, 1, 198],
              [19, 10, 1, 198],
              [83, 34, 1, 198],
              [69, 92, 1, 198]])

B_ref = np.array([[142, 159, 1, 198],
                  [77, 220, 1, 198],
                  [161, 88, 1, 198],
                  [188, 157, 1, 198]])

print("A:", A, "\n")

print("B_ref:", B_ref)
