import numpy as np
from numpy.typing import NDArray
import sys
sys.path.append('../')
from src.AES import AES
import galois

GF = galois.GF(2**8)


def mix_columns(matrix: NDArray[np.int8], shift: int) -> NDArray[np.int8]:
    """
    Preforms the shift columns (or inverse shift columns) operation on the input matrix.
    :param matrix: NDArray to preform shift columns on.
    :param shift: Integer of either -1 or 1 depending on direction of operation. (-1: Normal, 1: inverse)
    :return: NDArray.
    """
    cx: NDArray[np.int8] = np.array([[2, 3, 1, 1],  # Matrix used for shift columns operation
                                     [1, 2, 3, 1],
                                     [1, 1, 2, 3],
                                     [3, 1, 1, 2]])
    dx: NDArray[np.int8] = np.array([[14, 11, 13, 9],  # Matrix used for inverse shift columns operation
                                     [9, 14, 11, 13],
                                     [13, 9, 14, 11],
                                     [11, 13, 9, 14]])

    # Determines if preforming inverse operation or not
    if shift < 0:
        table = cx
    else:
        table = dx

        # GF(2^8) multiplication using AES irreducible polynomial
    def gf2mult(x, y):
        result = 0
        for i in range(8):
            if (y & 1) != 0:
                result = result ^ x
            b = (x & 0x80)
            x = (x << 1) & 0xFF
            if b:
                x = x ^ 0x1B
            y = (y >> 1) & 0xFF
        return result

    # Matrix multiplication done in GF(2^8)
    def mmult(matb):
        c = [None, None, None, None]
        c[0] = gf2mult(2, matb[0]) ^ gf2mult(3, matb[1]) ^ matb[2] ^ matb[3]
        c[1] = matb[0] ^ gf2mult(2, matb[1]) ^ gf2mult(3, matb[2]) ^ matb[3]
        c[2] = matb[0] ^ matb[1] ^ gf2mult(2, matb[2]) ^ gf2mult(3, matb[3])
        c[3] = gf2mult(3, matb[0]) ^ matb[1] ^ matb[2] ^ gf2mult(2, matb[3])

        return c

    for c in range(4):
        col = [
            matrix[0][c],
            matrix[1][c],
            matrix[2][c],
            matrix[3][c]
        ]
        col = mmult(col)
        matrix[0][c] = col[0]
        matrix[1][c] = col[1]
        matrix[2][c] = col[2]
        matrix[3][c] = col[3]

    # Preforms matrix multiplication with each column separately
    return matrix


A = np.array([[219, 242, 1, 198],
              [19, 10, 1, 198],
              [83, 34, 1, 198],
              [69, 92, 1, 198]])

B_ref = np.array([[142, 159, 1, 198],
                  [77, 220, 1, 198],
                  [161, 88, 1, 198],
                  [188, 157, 1, 198]])

print("A:", A, "\n")

print("B:", mix_columns(A, -1), "\n")

print("B_ref:", B_ref)
