from AES_Python import AES
import time
from typing import Callable


long_string = " En kort text för korta krypterings test och ännu kortare tider"
encrypted_string = "­ùkôªýí[¤{(¡.ÜSÁ`©Ý|ÁÆ¥°L2µzlt;K·~ú?òç áv?©«"


def timeit(func: Callable[[], None]) -> Callable[[], None]:
    def wrapper() -> None:
        t1: float = time.time()
        func()
        t2: float = (time.time() - t1) * 1000
        print(f'"{func.__name__}" ran in',
              f' {t2:.6f} ms.')
    return wrapper


@timeit
def custom_enc() -> None:
    aes = AES(running_mode="CBC", key="2b7e151628aed2a6abf7158809cf4f3c", iv="000102030405060708090a0b0c0d0e0f")
    aes.enc(data_string=long_string)


@timeit
def custom_dec() -> None:
    aes = AES(running_mode="CBC", key="2b7e151628aed2a6abf7158809cf4f3c", iv="000102030405060708090a0b0c0d0e0f")
    aes.dec(data_string=encrypted_string)


def main():
    custom_enc()
    custom_dec()


if __name__ == '__main__':
    main()
