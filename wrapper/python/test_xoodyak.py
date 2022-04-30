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
