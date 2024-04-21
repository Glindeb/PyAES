import pytest
import numpy as np
from numpy.typing import NDArray
from AES_Python import AES


@pytest.mark.parametrize("data,shift,expected", [(np.array([[99, 107, 103, 118],
                                                            [242, 1, 171, 123],
                                                            [48, 215, 119, 197],
                                                            [254, 124, 111, 43]]), -1,
                                                  np.array([[99, 1, 119, 43],
                                                            [242, 215, 111, 118],
                                                            [48, 124, 103, 123],
                                                            [254, 107, 171, 197]])),
                                                 (np.array([[99, 107, 103, 118],
                                                            [1, 171, 123, 242],
                                                            [119, 197, 48, 215],
                                                            [43, 254, 124, 111]]), 1,
                                                  np.array([[99, 254, 48, 242],
                                                            [1, 107, 124, 215],
                                                            [119, 171, 103, 111],
                                                            [43, 197, 123, 118]]))
                                                 ])
def test_shift_rows(data, shift, expected):
    result: NDArray[np.uint8] = AES()._AES__shift_rows(data, shift)  # type: ignore

    assert np.array_equal(result, expected)


@pytest.mark.parametrize("data,shift,expected", [(np.array([[219, 242, 1, 198],
                                                            [19, 10, 1, 198],
                                                            [83, 34, 1, 198],
                                                            [69, 92, 1, 198]]), -1,
                                                  np.array([[103, 225, 122, 18],
                                                            [255, 194, 74, 169],
                                                            [7, 210, 34, 65],
                                                            [169, 56, 74, 5]])),
                                                 (np.array([[142, 159, 1, 198],
                                                            [77, 220, 1, 198],
                                                            [161, 88, 1, 198],
                                                            [188, 157, 1, 198]]), 1,
                                                  np.array([[154, 251, 162, 21],
                                                            [143, 197, 111, 115],
                                                            [43, 113, 247, 147],
                                                            [171, 94, 193, 210]]))
                                                 ])
def test_mix_columns(data, shift, expected):
    result: NDArray[np.uint8] = AES()._AES__mix_columns(data, shift)    # type: ignore

    assert np.array_equal(result, expected)
