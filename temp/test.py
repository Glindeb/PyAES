import os
from AES_Python import AES

aes_test = AES(running_mode="CBC",
               key="2b7e151628aed2a6abf7158809cf4f3c",
               iv="000102030405060708090a0b0c0d0e0f"
               )

data = (b'\x1b\x16\x86:\xb9*w\xc5)"\xe4\xe9D\\\xf1\xee\x8b\x03\xcc\xe7\x0c~\xba7\xcf\x0f\x9c'
        b'\x16dM$\xe9\x91\xef\xc3\xa6\xd2\xf0\xcd\xc2\xee\x86\xf0\x90\x8a]\x87\xf5R\xe2.c\xd4'
        b'\xc6T\xdc\xe0#\xa7X\x8b_\x81\x04')
file_name = "tmp.txt"
expected = b'1234567890123456789012345678901234567890'

with open(f"{file_name}.enc", "wb") as file:
    file.write(data)

aes_test.dec(file_path=f"{file_name}.enc")

with open(f"{file_name}", "rb") as file:
    result = file.read()

os.remove(f"{file_name}")

print("Result:", result)
print("Expected:", expected)

rcon = [[0x00, 0x00, 0x00, 0x00],
        [0x01, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00],
        [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00],
        [0x80, 0x00, 0x00, 0x00],
        [0x1B, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00],
        [0x6c, 0x00, 0x00, 0x00],
        [0xd8, 0x00, 0x00, 0x00],
        [0xab, 0x00, 0x00, 0x00],
        [0x4d, 0x00, 0x00, 0x00],
        [0x9a, 0x00, 0x00, 0x00],
        ]

print(rcon)
