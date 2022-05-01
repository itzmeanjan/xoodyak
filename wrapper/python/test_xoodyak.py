#!/usr/bin/python3

import xoodyak as xdk
import numpy as np

u8 = np.uint8


def test_hash_kat():
    """
    Test functional correctness of Xoodyak cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests
    """
    count = 0

    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes(
                [
                    int(f"0x{msg[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(msg) >> 1)
                ]
            )

            md = bytes(
                [
                    int(f"0x{md[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(md) >> 1)
                ]
            )

            digest = xdk.hash(msg)

            assert (
                md == digest
            ), f"[Xoodyak Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()
            count = cnt

    print(f"[test] passed {count} -many Xoodyak Hash KAT(s)")


def test_aead_kat():
    """
    Test functional correctness of Xoodyak AEAD implementation,
    using Known Answer Tests found in NIST LWC submission package of Xoodyak.
    """
    count = 0  # -many KATs to be run

    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            tag = [i.strip() for i in ct.split("=")][-1][-32:]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # 128 -bit authentication tag
            tag = bytes(
                [
                    int(f"0x{tag[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(tag) >> 1)
                ]
            )

            cipher, tag_ = xdk.encrypt(key, nonce, ad, pt)
            flag, text = xdk.decrypt(key, nonce, tag_, ad, cipher)

            assert (
                pt == text and flag
            ), f"[Xoodyak KAT {cnt}] expected 0x{pt.hex()}, found 0x{text.hex()} !"

            assert (
                tag == tag_
            ), f"[Xoodyak KAT {cnt}] expected tag 0x{tag.hex()}, found 0x{tag_.hex()}"

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f"[test] passed {count} -many Xoodyak KAT(s)")


if __name__ == "__main__":
    print("Run Xoodak Known Answer Tests using `pytest` !")
