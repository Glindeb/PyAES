from time import time
from typing import Callable
from AES_Python import AES


def timeit(func: Callable[[], float]) -> Callable[[], None]:
    def wrapper() -> str:
        t1: float = time()
        value = func()
        t2: float = (time() - t1) * 1000
        print(f'"{func.__name__}" ran in',
              f' {t2:.6e} ms.')
        return value
    return wrapper


@timeit
def expand_128bit() -> str:
    key = AES.key_gen(16)
    return key, AES.key_expand(key)


@timeit
def expand_192bit() -> str:
    key = AES.key_gen(24)
    return key, AES.key_expand(key)


@timeit
def expand_256bit() -> str:
    key = AES.key_gen(32)
    return key, AES.key_expand(key)


def main():
    key_128bit = expand_128bit()
    print("Key_128bit:", key_128bit[0], "\nExpanded key:", key_128bit[1])

    key_192bit = expand_192bit()
    print("Key_192bit:", key_192bit[0], "\nExpanded key:", key_192bit[1])

    key_256bit = expand_256bit()
    print("Key_256bit:", key_256bit[0], "\nExpanded key:", key_256bit[1])


if __name__ == '__main__':
    main()
