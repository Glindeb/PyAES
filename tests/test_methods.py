import sys
import pytest
import numpy as np
from numpy.typing import NDArray

sys.path.append('../')
from src.AES import AES


@pytest.mark.parametrize("data,shift,expected", [(np.array([[99, 107, 103, 118],
                                                            [242, 1, 171, 123],
                                                            [48, 215, 119, 197],
                                                            [254, 124, 111, 43]]), -1,
                                                  np.array([[99, 107, 103, 118],
                                                            [1, 171, 123, 242],
                                                            [119, 197, 48, 215],
                                                            [43, 254, 124, 111]])),
                                                 (np.array([[99, 107, 103, 118],
                                                            [1, 171, 123, 242],
                                                            [119, 197, 48, 215],
                                                            [43, 254, 124, 111]]), 1,
                                                  np.array([[99, 107, 103, 118],
                                                            [242, 1, 171, 123],
                                                            [48, 215, 119, 197],
                                                            [254, 124, 111, 43]]))
                                                 ])
def test_shift_rows(data, shift, expected):
    result: NDArray[np.int8] = AES()._AES__shift_rows(data, shift)

    assert np.array_equal(result, expected)


@pytest.mark.parametrize("data,shift,expected", [(np.array([[219, 242, 1, 198],
                                                            [19, 10, 1, 198],
                                                            [83, 34, 1, 198],
                                                            [69, 92, 1, 198]]), -1,
                                                  np.array([[142, 159, 1, 198],
                                                            [77, 220, 1, 198],
                                                            [161, 88, 1, 198],
                                                            [188, 157, 1, 198]])),
                                                 (np.array([[142, 159, 1, 198],
                                                            [77, 220, 1, 198],
                                                            [161, 88, 1, 198],
                                                            [188, 157, 1, 198]]), 1,
                                                  np.array([[219, 242, 1, 198],
                                                            [19, 10, 1, 198],
                                                            [83, 34, 1, 198],
                                                            [69, 92, 1, 198]]))
                                                 ])
def test_mix_columns(data, shift, expected):
    result: NDArray[np.int8] = AES()._AES__mix_columns(data, shift)

    assert np.array_equal(result, expected)
