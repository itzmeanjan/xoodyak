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
2022-05-01T12:56:18+05:30
Running ./bench/a.out
Run on (4 X 1800 MHz CPU s)
Load Average: 2.08, 1.62, 1.22
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                1624 ns         1623 ns       430893 bytes_per_second=18.8083M/s items_per_second=616.312k/s
hash_64B                2703 ns         2701 ns       259709 bytes_per_second=22.5967M/s items_per_second=370.224k/s
hash_128B               4856 ns         4853 ns       144248 bytes_per_second=25.1521M/s items_per_second=206.046k/s
hash_256B               9140 ns         9134 ns        76253 bytes_per_second=26.7274M/s items_per_second=109.475k/s
hash_512B              17692 ns        17681 ns        39536 bytes_per_second=27.6156M/s items_per_second=56.5568k/s
hash_1024B             34827 ns        34804 ns        20104 bytes_per_second=28.059M/s items_per_second=28.7324k/s
hash_2048B             69142 ns        69084 ns        10074 bytes_per_second=28.2716M/s items_per_second=14.4751k/s
hash_4096B            138000 ns       137904 ns         5071 bytes_per_second=28.3258M/s items_per_second=7.25141k/s
encrypt_32B_64B         2842 ns         2840 ns       246751 bytes_per_second=32.2397M/s items_per_second=352.143k/s
encrypt_32B_128B        4561 ns         4560 ns       153488 bytes_per_second=33.4641M/s items_per_second=219.31k/s
encrypt_32B_256B        7508 ns         7493 ns        93049 bytes_per_second=36.6568M/s items_per_second=133.463k/s
encrypt_32B_512B       13929 ns        13919 ns        50197 bytes_per_second=37.2723M/s items_per_second=71.8435k/s
encrypt_32B_1024B      26020 ns        26004 ns        26613 bytes_per_second=38.728M/s items_per_second=38.4557k/s
encrypt_32B_2048B      51320 ns        51246 ns        13565 bytes_per_second=38.7081M/s items_per_second=19.5136k/s
encrypt_32B_4096B     100408 ns       100278 ns         6960 bytes_per_second=39.2587M/s items_per_second=9.97232k/s
decrypt_32B_64B         2833 ns         2832 ns       246742 bytes_per_second=32.3304M/s items_per_second=353.134k/s
decrypt_32B_128B        4600 ns         4597 ns       152423 bytes_per_second=33.1935M/s items_per_second=217.537k/s
decrypt_32B_256B        7655 ns         7650 ns        91801 bytes_per_second=35.9025M/s items_per_second=130.717k/s
decrypt_32B_512B       13929 ns        13924 ns        50078 bytes_per_second=37.2584M/s items_per_second=71.8166k/s
decrypt_32B_1024B      26934 ns        26913 ns        25977 bytes_per_second=37.4197M/s items_per_second=37.1566k/s
decrypt_32B_2048B      51258 ns        51226 ns        13536 bytes_per_second=38.7235M/s items_per_second=19.5214k/s
decrypt_32B_4096B     102996 ns       102940 ns         6851 bytes_per_second=38.2432M/s items_per_second=9.71437k/s
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
