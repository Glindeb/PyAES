import numpy as np
from numpy.typing import NDArray
import sys
sys.path.append('../')
from src.AES import AES

print(np.frombuffer(bytes.fromhex("ffffffffffffffffffffffffffffffff"), dtype=np.uint8))
# 8cd7c326
