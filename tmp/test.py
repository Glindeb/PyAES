import numpy as np
byte_data = b'\x01\x02\x03\x04'

print(byte_data[0])

array = np.frombuffer(byte_data, dtype=np.uint8)
print(array)
