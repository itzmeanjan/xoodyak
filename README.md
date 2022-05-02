# xoodyak
Accelerated Xoodyak - A Lightweight Cryptographic Scheme

## Overview

After implementing `ascon` & `tinyjambu` -- two finalists of NIST **L**ight **W**eight **C**ryptography competition, I've picked up `xoodyak`, which is another finalist of NIST LWC call. Xoodyak cryptograhic suite, as submitted in NIST LWC call, offers following two features

- **[Xoodyak Hash]** Computes cryptographically secure hash of input message M, of lenth N (>=0)
- **[Xoodyak AEAD]** Given 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes associated data & M (>=0) -bytes plain text data, one party computes M -bytes encrypted text, along with 16 -bytes authentication tag. Now other side of communication can perform verified decryption of encrypted plain text, when it has access to following pieces of information
  - 16 -bytes secret key
  - 16 -bytes nonce
  - 16 -bytes authentication tag
  - N -bytes associated data
  - M -bytes encrypted text

Receiving party can verify authenticity & integrity of encrypted message by asserting truth value in boolean flag returned from `decrypt(...)` routine. If verification flag is not truth value, decrypted text should never be consumed.

> Note, associated data is never encrypted

> AEAD -> Authenticated Encryption with Associated Data

In this repository, I'm keeping a simple, zero-dependency, easy-to-use header-only C++ library ( using C++20 features ), which implements Xoodyak specification. Along with that I also maintain Python wrapper API, which under the hood makes use of C-ABI conformant shared library object.

> To learn more about AEAD, see [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> If interested in my work on `ascon`, see [here](https://github.com/itzmeanjan/ascon)

> If interested in my work on `tinyjambu`, see [here](https://github.com/itzmeanjan/tinyjambu)

> Xoodyak specification, which I followed during this implementation, lives [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf)

## Prerequisites

- Ensure you've C++ compiler such as `dpcpp`/ `clang++`/ `g++`, with C++20 standard library specification implemented

> I'm using

```bash
$dpcpp --version

Intel(R) oneAPI DPC++/C++ Compiler 2022.0.0 (2022.0.0.20211123)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /opt/intel/oneapi/compiler/2022.0.2/linux/bin-llvm
```

```bash
$ g++ --version

g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- You should also have standard system development utilities such as `make`, `cmake`

> I'm using

```bash
$ make -v

GNU Make 4.2.1
```

```bash
$ cmake  --version

cmake version 3.16.3
```

- For benchmarking Xoodyak implementation on CPU, you'll need to have `google-benchmark` installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

- For using/ testing Python wrapper API of Xoodyak, you need to have `python3`, along with dependencies which can be easily installed using `pip`

> I'm using

```bash
$ python3 --version

Python 3.10.4
```

> Install Python dependencies

```bash
pushd wrapper/python
python3 -m pip install -r requirements.txt # ensure you've pip installed
popd
```

> It's better idea to isolate Xoodyak Python API dependency installation from system Python installation, using `virtualenv`

```bash
# install virtualenv itself
python3 -m pip install --user virtualenv

pushd wrapper/python
# create virtualenv enabled workspace
python3 -m virtualenv .

# activate virtual environment
source bin/activate
# install all dependencies inside virtual environment
python3 -m pip install -r requirements.txt

# work inside virtual environment
# when done, issue following command
# ...

deactivate
popd
```

## Testing

For testing functional correctness of Xoodyak cryptographic suite implementation, I've written following tests

- Given 16 -bytes random secret key, 16 -bytes random public message nonce, N (>=0) -bytes random associated data & M (>=0) -bytes random plain text
  - Ensure, in ideal condition, everything works as expected, while executing encrypt -> decrypt -> byte-by-byte comparison of plain & decrypted text
  - Same as above point, just that before attempting decryption, to check that claimed security properties are working as expected in this implementation, mutation of secret key/ nonce/ tag/ encrypted data/ associated data ( even a single bit flip is sufficient ) is performed, while asserting that verified decryption attempt must fail ( read boolean verification flag must not be truth value ).
- Given Known Answer Tests as submitted with Xoodyak package in NIST LWC call, this implementation computed results are asserted against KATs, to ensure correctness & conformance to specified standard. Both Xoodyak Hash & AEAD are checked.

For executing first kind of test, issue

```bash
make          # uses C++ API of Xoodyak
```

And if interested in testing against KAT, issue

```bash
make test_kat # uses Python API of Xoodyak
```

## Benchmarking

For benchmarking following implementations of Xoodyak cryptographic suite, on CPU

- Xoodyak cryptographic hash function
- Xoodyak Authenticated Encryption
- Xoodyak Verified Decryption

issue

```bash
make benchmark # must have `google-benchmark`
```

### On ARM Cortex A72

```bash
2022-05-02T08:49:59+05:30
Running ./bench/a.out
Run on (4 X 1800 MHz CPU s)
Load Average: 2.56, 3.57, 2.64
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                1292 ns         1288 ns       546293 bytes_per_second=23.6973M/s items_per_second=776.514k/s
hash_64B                2103 ns         2100 ns       332950 bytes_per_second=29.0585M/s items_per_second=476.095k/s
hash_128B               3804 ns         3804 ns       183945 bytes_per_second=32.0888M/s items_per_second=262.872k/s
hash_256B               7154 ns         7149 ns        96973 bytes_per_second=34.1488M/s items_per_second=139.873k/s
hash_512B              13933 ns        13929 ns        50244 bytes_per_second=35.0552M/s items_per_second=71.793k/s
hash_1024B             27450 ns        27449 ns        25498 bytes_per_second=35.5771M/s items_per_second=36.4309k/s
hash_2048B             54638 ns        54631 ns        12878 bytes_per_second=35.751M/s items_per_second=18.3045k/s
hash_4096B            108240 ns       108179 ns         6450 bytes_per_second=36.1092M/s items_per_second=9.24395k/s
encrypt_32B_64B         2306 ns         2306 ns       305559 bytes_per_second=39.7065M/s items_per_second=433.701k/s
encrypt_32B_128B        3712 ns         3709 ns       187964 bytes_per_second=41.1377M/s items_per_second=269.6k/s
encrypt_32B_256B        6123 ns         6122 ns       114814 bytes_per_second=44.8657M/s items_per_second=163.351k/s
encrypt_32B_512B       11378 ns        11378 ns        60919 bytes_per_second=45.5985M/s items_per_second=87.8924k/s
encrypt_32B_1024B      21359 ns        21358 ns        32730 bytes_per_second=47.1527M/s items_per_second=46.8212k/s
encrypt_32B_2048B      42039 ns        42016 ns        16734 bytes_per_second=47.2111M/s items_per_second=23.8002k/s
encrypt_32B_4096B      82883 ns        82876 ns         8489 bytes_per_second=47.5016M/s items_per_second=12.0662k/s
decrypt_32B_64B         2283 ns         2283 ns       307477 bytes_per_second=40.1053M/s items_per_second=438.057k/s
decrypt_32B_128B        3785 ns         3784 ns       185221 bytes_per_second=40.3239M/s items_per_second=264.266k/s
decrypt_32B_256B        6201 ns         6200 ns       105630 bytes_per_second=44.3002M/s items_per_second=161.292k/s
decrypt_32B_512B       11453 ns        11452 ns        60904 bytes_per_second=45.3031M/s items_per_second=87.323k/s
decrypt_32B_1024B      21672 ns        21663 ns        30196 bytes_per_second=46.4887M/s items_per_second=46.1618k/s
decrypt_32B_2048B      42371 ns        42306 ns        16535 bytes_per_second=46.888M/s items_per_second=23.6373k/s
decrypt_32B_4096B      86808 ns        86641 ns         8443 bytes_per_second=45.4375M/s items_per_second=11.5418k/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-05-01T07:34:18+00:00
Running ./bench/a.out
Run on (4 X 2300.07 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.08, 0.02, 0.01
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                 465 ns          465 ns      1506912 bytes_per_second=65.6857M/s items_per_second=2.15239M/s
hash_64B                 776 ns          776 ns       900928 bytes_per_second=78.64M/s items_per_second=1.28844M/s
hash_128B               1396 ns         1396 ns       501084 bytes_per_second=87.4257M/s items_per_second=716.191k/s
hash_256B               2634 ns         2634 ns       265735 bytes_per_second=92.6943M/s items_per_second=379.676k/s
hash_512B               5117 ns         5117 ns       136725 bytes_per_second=95.4322M/s items_per_second=195.445k/s
hash_1024B             10079 ns        10078 ns        69482 bytes_per_second=96.8969M/s items_per_second=99.2224k/s
hash_2048B             19989 ns        19989 ns        34888 bytes_per_second=97.7103M/s items_per_second=50.0277k/s
hash_4096B             39820 ns        39817 ns        17573 bytes_per_second=98.1049M/s items_per_second=25.1149k/s
encrypt_32B_64B          839 ns          839 ns       834154 bytes_per_second=109.108M/s items_per_second=1.19175M/s
encrypt_32B_128B        1348 ns         1348 ns       523189 bytes_per_second=113.16M/s items_per_second=741.605k/s
encrypt_32B_256B        2186 ns         2186 ns       320184 bytes_per_second=125.673M/s items_per_second=457.561k/s
encrypt_32B_512B        4048 ns         4048 ns       172988 bytes_per_second=128.152M/s items_per_second=247.018k/s
encrypt_32B_1024B       7613 ns         7613 ns        92006 bytes_per_second=132.291M/s items_per_second=131.361k/s
encrypt_32B_2048B      14880 ns        14879 ns        47040 bytes_per_second=133.314M/s items_per_second=67.2068k/s
encrypt_32B_4096B      30435 ns        30434 ns        23025 bytes_per_second=129.353M/s items_per_second=32.8577k/s
decrypt_32B_64B          874 ns          874 ns       801116 bytes_per_second=104.729M/s items_per_second=1.14392M/s
decrypt_32B_128B        1377 ns         1377 ns       504551 bytes_per_second=110.805M/s items_per_second=726.172k/s
decrypt_32B_256B        2249 ns         2249 ns       311649 bytes_per_second=122.129M/s items_per_second=444.657k/s
decrypt_32B_512B        4107 ns         4107 ns       170027 bytes_per_second=126.314M/s items_per_second=243.475k/s
decrypt_32B_1024B       7785 ns         7785 ns        89754 bytes_per_second=129.364M/s items_per_second=128.455k/s
decrypt_32B_2048B      15248 ns        15247 ns        45901 bytes_per_second=130.099M/s items_per_second=65.5857k/s
decrypt_32B_4096B      30294 ns        30293 ns        23118 bytes_per_second=129.957M/s items_per_second=33.0111k/s
```

## Usage

Xoodyak being a header-only C++ library, using it is as easy as including [`xoodyak.hpp`](https://github.com/itzmeanjan/xoodyak/blob/f366012/include/xoodyak.hpp) in your C++ program & adding `./include` to your include path. I've written two examples demonstrating usage of Xoodyak C++ API

- Xoodyak Hash; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_hash.cpp) 
- Xoodyak AEAD; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_aead.cpp)
