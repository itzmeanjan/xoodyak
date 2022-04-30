#!/usr/bin/python3

"""
  Before using `xoodyak` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/tinyjambu
"""

import ctypes as ct
import numpy as np
from posixpath import exists, abspath

# shared library object path
SO_PATH: str = abspath("../libxoodyak.so")
# enforce presence of shared library object
assert exists(SO_PATH), "Use `make lib` to generate shared library object !"
# shared library object
SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

# prepare data types for input/ output of C++ functions
u8 = np.uint8
len_t = ct.c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags="CONTIGUOUS")


def hash(msg: bytes) -> bytes:
    """
    Given a N ( >= 0 ) -bytes input message, this function computes 32 -bytes
    Xoodyak cryptographic hash
    """
    m_len = len(msg)
    msg_ = np.frombuffer(msg, dtype=u8)
    digest = np.empty(32, dtype=u8)

    args = [uint8_tp, len_t, uint8_tp]
    SO_LIB.hash.argtypes = args

    SO_LIB.hash(msg_, m_len, digest)

    digest_ = digest.tobytes()

    return digest_


if __name__ == "__main__":
    print("Use `xoodyak` as library module !")
