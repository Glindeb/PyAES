from time import time
from typing import Callable
from AES_Python import AES


def timeit(func: Callable[[], float]) -> Callable[[], None]:
    def wrapper() -> None:
        t1: float = time()
        func()
        t2: float = (time() - t1) * 1000
        print(f'"{func.__name__}" ran in',
              f' {t2:.6e} ms.')
    return wrapper


@timeit
def expand_128bit():
    AES.key_expand(AES.key_gen(16))


@timeit
def expand_192bit():
    AES.key_expand(AES.key_gen(24))


@timeit
def expand_256bit():
    AES.key_expand(AES.key_gen(32))


def main():
    expand_128bit()
    expand_192bit()
    expand_256bit()


if __name__ == '__main__':
    main()
