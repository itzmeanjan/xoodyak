#!/usr/bin/python3

"""
  Before using `xoodyak` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/xoodyak
"""

import ctypes as ct
from typing import Tuple
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
bool_t = ct.c_bool


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


def encrypt(key: bytes, nonce: bytes, data: bytes, text: bytes) -> Tuple[bytes, bytes]:
    """
    Given 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes associated data
    & M (>=0) -bytes plain text, this routine produces M -bytes cipher text & 16 -bytes
    authentication tag ( in order )
    """
    k_len = len(key)
    n_len = len(nonce)
    d_len = len(data)
    t_len = len(text)

    assert k_len == 16, "Xoodyak AEAD takes 16 -bytes secret key"
    assert n_len == 16, "Xoodyak AEAD takes 16 -bytes nonce"

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    text_ = np.frombuffer(text, dtype=u8)
    enc = np.empty(t_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, len_t, uint8_tp, uint8_tp, len_t, uint8_tp]
    SO_LIB.encrypt.argtypes = args

    SO_LIB.encrypt(key_, nonce_, data_, d_len, text_, enc, t_len, tag)

    enc_ = enc.tobytes()
    tag_ = tag.tobytes()

    return enc_, tag_


def decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag,
    N (>=0) -bytes associated data & M (>=0) -bytes encrypted data, this routine produces
    boolean verification flag & M -bytes plain text ( in order )
    """
    k_len = len(key)
    n_len = len(nonce)
    t_len = len(nonce)
    dt_len = len(data)
    ct_len = len(enc)

    assert k_len == 16, "Xoodyak AEAD takes 16 -bytes secret key"
    assert n_len == 16, "Xoodyak AEAD takes 16 -bytes nonce"
    assert t_len == 16, "Xoodyak AEAD takes 16 -bytes authentication tag"

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    tag_ = np.frombuffer(tag, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    enc_ = np.frombuffer(enc, dtype=u8)
    dec = np.empty(ct_len, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, uint8_tp, len_t, uint8_tp, uint8_tp, len_t]
    SO_LIB.decrypt.argtypes = args
    SO_LIB.decrypt.restypes = bool_t

    f = SO_LIB.decrypt(key_, nonce_, tag_, data_, dt_len, enc_, dec, ct_len)

    dec_ = dec.tobytes()

    return f, dec_


if __name__ == "__main__":
    print("Use `xoodyak` as library module !")
