# xoodyak
Accelerated Xoodyak - A Lightweight Cryptographic Scheme

## Overview

After implementing `ascon` & `tinyjambu` -- two finalists of NIST **L**ight **W**eight **C**ryptography standardization competition, I've picked up `xoodyak`, which is another finalist of NIST LWC call. Xoodyak cryptograhic suite, as submitted in NIST LWC call, offers following two features

- Cryptographic Hashing
- Authenticated Encryption with Associated Data ( AEAD )

Algorithm | What does it do ? | Input | Output
--- | :-- | --: | --:
**Xoodyak Hash** | Computes cryptographically secure digest of message | N (>=0) -bytes message | 32 -bytes digest
**Xoodyak AEAD Encrypt** | Encrypts message while authenticating both message and associated data | 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes associated data and M (>=0) -bytes plain text | M (>=0) -bytes encrypted text and 16 -bytes authentication tag
**Xoodyak AEAD Decrypt** | Decrypts message while verifying authenticity of both message and associated data | 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N (>=0) -bytes associated data and M (>=0) -bytes encrypted text | M (>=0) -bytes plain text and boolean verification flag

> **Note** Decrypting party can verify authenticity & integrity of encrypted message and associated data by asserting truth value in boolean flag returned from `decrypt(...)` routine. If verification flag is not truth value, decrypted text is not released.

> **Warning** Associated data is never encrypted.

In this repository, I'm keeping a zero-dependency, header-only and easy-to-use C++ library ( using C++20 features ), which implements Xoodyak specification. Along with that I also maintain Python wrapper API, which under the hood makes use of C-ABI conformant shared library object.

> To learn more about AEAD, see [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> If interested in my work on `ascon`, see [here](https://github.com/itzmeanjan/ascon)

> If interested in my work on `tinyjambu`, see [here](https://github.com/itzmeanjan/tinyjambu)

> **Note** Xoodyak specification, which I followed during this implementation, lives [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf)

## Prerequisites

- Ensure you've C++ compiler such as `clang++`/ `g++`, with C++20 standard library

```bash
$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: aarch64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/bin

$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- You should also have system development utilities such as `make`, `cmake`, `git` & `unzip`

```bash
$ make --version
GNU Make 4.3

$ cmake --version
cmake version 3.22.1

$ git --version
git version 2.34.1

$ unzip -v
UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.
```

- For benchmarking Xoodyak implementation on CPU, you'll need to have `google-benchmark` headers and library installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

- For ensuring conformance with KATs ( as submitted to NIST LWC call ), you need to have `python3`, along with dependencies which can be easily installed using `pip`

```bash
$ python3 --version
Python 3.10.8

# If you don't have pip installed
$ sudo apt-get install python3-pip

# Download Python dependencies
$ python3 -m pip install -r wrapper/python/requirements.txt --user
```

> **Note** It can be a better idea to isolate Xoodyak Python API dependency installation from system Python installation, using `virtualenv`

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

- [ **test_aead** ] : Given 16 -bytes random secret key, 16 -bytes random public message nonce, N (>=0) -bytes random associated data & M (>=0) -bytes random plain text
  - Ensure, in ideal condition, everything works as expected, while executing encrypt -> decrypt -> byte-by-byte comparison of plain & decrypted text
  - Same as above point, just that before attempting decryption, to check that claimed security properties are working as expected in this implementation, mutation of secret key/ nonce/ tag/ encrypted data/ associated data ( even a single bit flip is sufficient ) is performed, while asserting that verified decryption attempt must fail ( read boolean verification flag must not be truth value ).
- [ **test_kat** ] : Given Known Answer Tests as submitted with Xoodyak package in NIST LWC call, this implementation computed results are asserted against KATs, to ensure correctness & conformance to specified standard. Both Xoodyak Hash & AEAD are checked.

```bash
# Just issue 

make            # test_aead + test_kat
SSE2=1 make     # if target CPU has SSE2

# --- Or you may ---

make test_aead         # tests functional correctness of AEAD
SSE2=1 make test_aead  # if target CPU has SSE2

make test_kat          # tests correctness and conformance with standard
SSE2=1 make test_kat   # if target CPU has SSE2
```

## Benchmarking

For benchmarking following implementations of Xoodyak cryptographic suite, on CPU

- Xoodoo[12] permutation
- Xoodyak cryptographic hash function
- Xoodyak Authenticated Encryption
- Xoodyak Verified Decryption

issue

```bash
make benchmark        # must have `google-benchmark` library and header
SSE2=1 make benchmark # if target CPU has SSE2
```

### On Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz ( compiled with GCC )

```bash
2023-01-09T16:46:47+00:00
Running ./bench/a.out
Run on (128 X 1343.45 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x64)
  L1 Instruction 32 KiB (x64)
  L2 Unified 1280 KiB (x64)
  L3 Unified 55296 KiB (x2)
Load Average: 0.30, 0.10, 0.03
-----------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------
bench_xoodyak::hash/64                792 ns          792 ns       884350 bytes_per_second=77.1079M/s
bench_xoodyak::hash/128              1408 ns         1408 ns       497356 bytes_per_second=86.6982M/s
bench_xoodyak::hash/256              2644 ns         2644 ns       264858 bytes_per_second=92.3503M/s
bench_xoodyak::hash/512              5113 ns         5113 ns       136861 bytes_per_second=95.4947M/s
bench_xoodyak::hash/1024            10044 ns        10044 ns        69715 bytes_per_second=97.2304M/s
bench_xoodyak::hash/2048            19912 ns        19913 ns        35153 bytes_per_second=98.0851M/s
bench_xoodyak::hash/4096            39644 ns        39645 ns        17660 bytes_per_second=98.5307M/s
bench_xoodyak::encrypt/32/64          605 ns          605 ns      1156776 bytes_per_second=151.371M/s
bench_xoodyak::decrypt/32/64          606 ns          606 ns      1154334 bytes_per_second=150.965M/s
bench_xoodyak::encrypt/32/128         953 ns          953 ns       733726 bytes_per_second=160.148M/s
bench_xoodyak::decrypt/32/128         958 ns          958 ns       729611 bytes_per_second=159.307M/s
bench_xoodyak::encrypt/32/256        1551 ns         1551 ns       451123 bytes_per_second=177.068M/s
bench_xoodyak::decrypt/32/256        1556 ns         1556 ns       451385 bytes_per_second=176.484M/s
bench_xoodyak::encrypt/32/512        2823 ns         2823 ns       247997 bytes_per_second=183.789M/s
bench_xoodyak::decrypt/32/512        2837 ns         2837 ns       246746 bytes_per_second=182.886M/s
bench_xoodyak::encrypt/32/1024       5252 ns         5252 ns       133334 bytes_per_second=191.759M/s
bench_xoodyak::decrypt/32/1024       5298 ns         5297 ns       131890 bytes_per_second=190.109M/s
bench_xoodyak::encrypt/32/2048      10232 ns        10232 ns        68414 bytes_per_second=193.864M/s
bench_xoodyak::decrypt/32/2048      10326 ns        10326 ns        67752 bytes_per_second=192.103M/s
bench_xoodyak::encrypt/32/4096      20099 ns        20099 ns        34825 bytes_per_second=195.871M/s
bench_xoodyak::decrypt/32/4096      20251 ns        20251 ns        34560 bytes_per_second=194.395M/s
```

### On Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz ( compiled with Clang )

```bash
2023-01-09T16:47:33+00:00
Running ./bench/a.out
Run on (128 X 2722.43 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x64)
  L1 Instruction 32 KiB (x64)
  L2 Unified 1280 KiB (x64)
  L3 Unified 55296 KiB (x2)
Load Average: 0.38, 0.16, 0.06
-----------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------
bench_xoodyak::hash/64                434 ns          434 ns      1613281 bytes_per_second=140.674M/s
bench_xoodyak::hash/128               781 ns          781 ns       896393 bytes_per_second=156.346M/s
bench_xoodyak::hash/256              1474 ns         1474 ns       474787 bytes_per_second=165.625M/s
bench_xoodyak::hash/512              2861 ns         2861 ns       244530 bytes_per_second=170.677M/s
bench_xoodyak::hash/1024             5636 ns         5637 ns       124155 bytes_per_second=173.255M/s
bench_xoodyak::hash/2048            11186 ns        11186 ns        62585 bytes_per_second=174.608M/s
bench_xoodyak::hash/4096            22287 ns        22286 ns        31399 bytes_per_second=175.275M/s
bench_xoodyak::encrypt/32/64          468 ns          468 ns      1494075 bytes_per_second=195.42M/s
bench_xoodyak::decrypt/32/64          478 ns          478 ns      1462550 bytes_per_second=191.367M/s
bench_xoodyak::encrypt/32/128         774 ns          774 ns       905020 bytes_per_second=197.239M/s
bench_xoodyak::decrypt/32/128         800 ns          800 ns       875634 bytes_per_second=190.82M/s
bench_xoodyak::encrypt/32/256        1283 ns         1283 ns       545553 bytes_per_second=214.09M/s
bench_xoodyak::decrypt/32/256        1322 ns         1322 ns       529471 bytes_per_second=207.727M/s
bench_xoodyak::encrypt/32/512        2400 ns         2400 ns       291649 bytes_per_second=216.161M/s
bench_xoodyak::decrypt/32/512        2482 ns         2482 ns       281992 bytes_per_second=209.011M/s
bench_xoodyak::encrypt/32/1024       4532 ns         4532 ns       154451 bytes_per_second=222.221M/s
bench_xoodyak::decrypt/32/1024       4680 ns         4680 ns       149556 bytes_per_second=215.182M/s
bench_xoodyak::encrypt/32/2048       8885 ns         8885 ns        78785 bytes_per_second=223.248M/s
bench_xoodyak::decrypt/32/2048       9211 ns         9211 ns        76008 bytes_per_second=215.345M/s
bench_xoodyak::encrypt/32/4096      17470 ns        17470 ns        40061 bytes_per_second=225.346M/s
bench_xoodyak::decrypt/32/4096      18108 ns        18108 ns        38657 bytes_per_second=217.407M/s
```

### On ARM Neoverse-V1 aka AWS Graviton3 ( compiled with GCC )

```bash
2023-01-09T16:54:26+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.15, 0.07, 0.02
-----------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------
bench_xoodyak::hash/64                579 ns          579 ns      1208366 bytes_per_second=105.483M/s
bench_xoodyak::hash/128              1046 ns         1046 ns       668895 bytes_per_second=116.663M/s
bench_xoodyak::hash/256              1979 ns         1979 ns       353725 bytes_per_second=123.366M/s
bench_xoodyak::hash/512              3845 ns         3845 ns       182039 bytes_per_second=126.983M/s
bench_xoodyak::hash/1024             7573 ns         7573 ns        92427 bytes_per_second=128.951M/s
bench_xoodyak::hash/2048            15036 ns        15035 ns        46556 bytes_per_second=129.901M/s
bench_xoodyak::hash/4096            29927 ns        29927 ns        23391 bytes_per_second=130.527M/s
bench_xoodyak::encrypt/32/64          598 ns          598 ns      1169735 bytes_per_second=153.043M/s
bench_xoodyak::decrypt/32/64          611 ns          611 ns      1147721 bytes_per_second=149.921M/s
bench_xoodyak::encrypt/32/128         977 ns          977 ns       715356 bytes_per_second=156.106M/s
bench_xoodyak::decrypt/32/128         995 ns          995 ns       704696 bytes_per_second=153.341M/s
bench_xoodyak::encrypt/32/256        1613 ns         1613 ns       434163 bytes_per_second=170.267M/s
bench_xoodyak::decrypt/32/256        1633 ns         1633 ns       427684 bytes_per_second=168.2M/s
bench_xoodyak::encrypt/32/512        2993 ns         2993 ns       233587 bytes_per_second=173.316M/s
bench_xoodyak::decrypt/32/512        3024 ns         3023 ns       232218 bytes_per_second=171.591M/s
bench_xoodyak::encrypt/32/1024       5624 ns         5624 ns       124487 bytes_per_second=179.059M/s
bench_xoodyak::decrypt/32/1024       5667 ns         5667 ns       123696 bytes_per_second=177.713M/s
bench_xoodyak::encrypt/32/2048      11010 ns        11010 ns        63574 bytes_per_second=180.174M/s
bench_xoodyak::decrypt/32/2048      11050 ns        11050 ns        63354 bytes_per_second=179.516M/s
bench_xoodyak::encrypt/32/4096      21658 ns        21657 ns        32322 bytes_per_second=181.781M/s
bench_xoodyak::decrypt/32/4096      21701 ns        21700 ns        32257 bytes_per_second=181.42M/s
```

### On ARM Neoverse-V1 aka AWS Graviton3 ( compiled with Clang )

```bash
2023-01-09T16:55:18+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.19, 0.10, 0.04
-----------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------
bench_xoodyak::hash/64                445 ns          445 ns      1572726 bytes_per_second=137.204M/s
bench_xoodyak::hash/128               806 ns          806 ns       868634 bytes_per_second=151.458M/s
bench_xoodyak::hash/256              1525 ns         1525 ns       459750 bytes_per_second=160.068M/s
bench_xoodyak::hash/512              2958 ns         2957 ns       236887 bytes_per_second=165.103M/s
bench_xoodyak::hash/1024             5819 ns         5818 ns       120339 bytes_per_second=167.839M/s
bench_xoodyak::hash/2048            11543 ns        11543 ns        60683 bytes_per_second=169.208M/s
bench_xoodyak::hash/4096            23030 ns        23029 ns        30406 bytes_per_second=169.623M/s
bench_xoodyak::encrypt/32/64          467 ns          467 ns      1497982 bytes_per_second=195.933M/s
bench_xoodyak::decrypt/32/64          475 ns          475 ns      1473104 bytes_per_second=192.617M/s
bench_xoodyak::encrypt/32/128         756 ns          756 ns       925961 bytes_per_second=201.88M/s
bench_xoodyak::decrypt/32/128         767 ns          767 ns       913262 bytes_per_second=198.973M/s
bench_xoodyak::encrypt/32/256        1240 ns         1240 ns       564311 bytes_per_second=221.46M/s
bench_xoodyak::decrypt/32/256        1251 ns         1251 ns       559039 bytes_per_second=219.576M/s
bench_xoodyak::encrypt/32/512        2270 ns         2269 ns       308416 bytes_per_second=228.599M/s
bench_xoodyak::decrypt/32/512        2301 ns         2301 ns       304218 bytes_per_second=225.483M/s
bench_xoodyak::encrypt/32/1024       4285 ns         4285 ns       163224 bytes_per_second=235.031M/s
bench_xoodyak::decrypt/32/1024       4333 ns         4333 ns       161467 bytes_per_second=232.445M/s
bench_xoodyak::encrypt/32/2048       8339 ns         8339 ns        83993 bytes_per_second=237.882M/s
bench_xoodyak::decrypt/32/2048       8460 ns         8460 ns        82630 bytes_per_second=234.482M/s
bench_xoodyak::encrypt/32/4096      16439 ns        16438 ns        42587 bytes_per_second=239.49M/s
bench_xoodyak::decrypt/32/4096      16637 ns        16637 ns        42090 bytes_per_second=236.63M/s
```

## Usage

Xoodyak being a header-only C++ library, using it is as easy as including [`xoodyak.hpp`](./include/xoodyak.hpp) in your C++ program & adding `./include` to your include path. All the functions of interest live under namespace `xoodyak::`. You may find some useful utility functions in [`utils.hpp`](./include/utils.hpp). I've written two examples demonstrating usage of Xoodyak C++ API

- Xoodyak Hash; see [here](./example/xoodyak_hash.cpp)

```bash
# Use scalar implementation of Xoodoo permutation
$ g++ -std=c++20 -Wall -Wextra -O3 -march=native -mtune=native -I ./include example/xoodyak_hash.cpp && ./a.out
# Or you may want to use SSE2 implementation of Xoodoo permutation
$ g++ -std=c++20 -Wall -Wextra -O3 -march=native -mtune=native -DUSE_SSE2=1 -I ./include example/xoodyak_hash.cpp && ./a.out

Message         : 550398b821a1915461c061935f43b64244f00bf7b5e325d61ebba4aa1acf82455815b4605e57be4c2aec85c13074424ae1cd688d28f637ae9e7ae2900b764282
Xoodyak Digest  : cf90c727933c5e68555e8f27c7440192854d476f436ab5b4d27c7df3ed5fdafd
```

- Xoodyak AEAD; see [here](./example/xoodyak_aead.cpp)

```bash
# With scalar implementation of Xoodoo permutation
g++ -std=c++20 -Wall -Wextra -O3 -march=native -mtune=native -I ./include example/xoodyak_aead.cpp && ./a.out
# With SSE2 implementation of Xoodoo permutation
g++ -std=c++20 -Wall -Wextra -O3 -march=native -mtune=native -DUSE_SSE2=1 -I ./include example/xoodyak_aead.cpp && ./a.out

Xoodyak AEAD

Key                : e5a7bad5128170584b5ba804b559a234
Nonce              : 74a9c38c241ac134b87dba198879d81a
Associated Data    : ae4e344a85b5d767327e9fbaa16b58bffa2c3a8b0f4d30d14ed6aaf35e5ecb4f
Plain Text         : 60e8a3bd1e51b59e769208826f9adb6eedabf8a9c2402a71704c830e03be3b1aa80cc4795a522731a72e2fa1b5258093f2a46d105a057d8c4dbb092264a65e37
Authentication Tag : 654649376b73ffffa09545c548271d66
Encrypted Text     : 8101b6d1ff84dc5ff91cea283263e753c7cb8898175d2521c346cd6181a46757157db4207a244a502e5429350f8e4e79249dc90d14300c8e39a7f4823633e768
Decrypted Text     : 60e8a3bd1e51b59e769208826f9adb6eedabf8a9c2402a71704c830e03be3b1aa80cc4795a522731a72e2fa1b5258093f2a46d105a057d8c4dbb092264a65e37
```
