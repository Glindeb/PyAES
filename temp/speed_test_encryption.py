from AES_Python import AES
import os
import time
from typing import Callable


def timeit(func: Callable[[], None]) -> Callable[[], None]:
    def wrapper() -> None:
        t1: float = time.time()
        func()
        t2: float = (time.time() - t1)
        print(f'"{func.__name__}" ran in',
              f' {t2:.2f} s.')
    return wrapper


@timeit
def enc() -> None:
    os.system("head -n 3 /Users/gabriel/Documents/GitHub/AES-Python/temp/test_image_low.ppm > /Users/gabriel/Documents/GitHub/AES-Python/temp/header.txt")
    os.system("tail -n +4 /Users/gabriel/Documents/GitHub/AES-Python/temp/test_image_low.ppm > /Users/gabriel/Documents/GitHub/AES-Python/temp/body.bin")

    aes = AES(running_mode="CBC", key="2b7e151628aed2a6abf7158809cf4f3c", iv="000102030405060708090a0b0c0d0e0f")
    aes.enc(file_path="/Users/gabriel/Documents/GitHub/AES-Python/temp/body.bin")

    os.system("cat /Users/gabriel/Documents/GitHub/AES-Python/temp/header.txt /Users/gabriel/Documents/GitHub/AES-Python/temp/body.bin.enc > /Users/gabriel/Documents/GitHub/AES-Python/temp/test_image_low.ppm")


@timeit
def dec() -> None:
    os.system("head -n 3 /Users/gabriel/Documents/GitHub/AES-Python/temp/test_image_low.ppm > /Users/gabriel/Documents/GitHub/AES-Python/temp/header.txt")

    aes = AES(running_mode="CBC", key="2b7e151628aed2a6abf7158809cf4f3c", iv="000102030405060708090a0b0c0d0e0f")
    aes.dec(file_path="/Users/gabriel/Documents/GitHub/AES-Python/temp/body.bin.enc")

    os.system("cat /Users/gabriel/Documents/GitHub/AES-Python/temp/header.txt /Users/gabriel/Documents/GitHub/AES-Python/temp/body.bin > /Users/gabriel/Documents/GitHub/AES-Python/temp/test_image_low.ppm")


if __name__ == '__main__':
    dec()
