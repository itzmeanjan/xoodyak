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
2022-05-04T12:09:53+05:30
Running ./bench/a.out
Run on (4 X 1800 MHz CPU s)
Load Average: 0.88, 1.18, 1.67
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                 975 ns          974 ns       716823 bytes_per_second=31.3252M/s items_per_second=1026.46k/s
hash_64B                1617 ns         1615 ns       432993 bytes_per_second=37.7816M/s items_per_second=619.014k/s
hash_128B               2908 ns         2906 ns       240757 bytes_per_second=42.0107M/s items_per_second=344.151k/s
hash_256B               5474 ns         5471 ns       127616 bytes_per_second=44.6268M/s items_per_second=182.791k/s
hash_512B              10607 ns        10599 ns        65924 bytes_per_second=46.0669M/s items_per_second=94.345k/s
hash_1024B             20869 ns        20856 ns        33518 bytes_per_second=46.8239M/s items_per_second=47.9477k/s
hash_2048B             41399 ns        41377 ns        16910 bytes_per_second=47.2035M/s items_per_second=24.1682k/s
hash_4096B             82453 ns        82407 ns         8471 bytes_per_second=47.402M/s items_per_second=12.1349k/s
encrypt_32B_64B         1684 ns         1682 ns       416046 bytes_per_second=54.4308M/s items_per_second=594.529k/s
encrypt_32B_128B        2699 ns         2698 ns       259665 bytes_per_second=56.5639M/s items_per_second=370.697k/s
encrypt_32B_256B        4467 ns         4424 ns       157763 bytes_per_second=62.0854M/s items_per_second=226.046k/s
encrypt_32B_512B        8169 ns         8119 ns        86521 bytes_per_second=63.8964M/s items_per_second=123.162k/s
encrypt_32B_1024B      15215 ns        15169 ns        46026 bytes_per_second=66.3911M/s items_per_second=65.9243k/s
encrypt_32B_2048B      29597 ns        29594 ns        23626 bytes_per_second=67.0282M/s items_per_second=33.7905k/s
encrypt_32B_4096B      58334 ns        58323 ns        11962 bytes_per_second=67.4991M/s items_per_second=17.1458k/s
decrypt_32B_64B         1687 ns         1687 ns       414496 bytes_per_second=54.2758M/s items_per_second=592.837k/s
decrypt_32B_128B        2708 ns         2708 ns       258451 bytes_per_second=56.3549M/s items_per_second=369.327k/s
decrypt_32B_256B        4388 ns         4388 ns       159496 bytes_per_second=62.5987M/s items_per_second=227.915k/s
decrypt_32B_512B        8094 ns         8091 ns        86539 bytes_per_second=64.1212M/s items_per_second=123.596k/s
decrypt_32B_1024B      15163 ns        15162 ns        46191 bytes_per_second=66.4199M/s items_per_second=65.9529k/s
decrypt_32B_2048B      29648 ns        29645 ns        23635 bytes_per_second=66.9136M/s items_per_second=33.7327k/s
decrypt_32B_4096B      58251 ns        58244 ns        12016 bytes_per_second=67.5911M/s items_per_second=17.1692k/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-05-04T06:47:49+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.18, 0.12, 0.04
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                 449 ns          449 ns      1558660 bytes_per_second=67.9419M/s items_per_second=2.22632M/s
hash_64B                 748 ns          748 ns       936820 bytes_per_second=81.6343M/s items_per_second=1.3375M/s
hash_128B               1344 ns         1344 ns       520019 bytes_per_second=90.8177M/s items_per_second=743.979k/s
hash_256B               2552 ns         2552 ns       274267 bytes_per_second=95.6766M/s items_per_second=391.891k/s
hash_512B               4943 ns         4942 ns       141636 bytes_per_second=98.7935M/s items_per_second=202.329k/s
hash_1024B              9727 ns         9727 ns        71968 bytes_per_second=100.399M/s items_per_second=102.808k/s
hash_2048B             19308 ns        19308 ns        36252 bytes_per_second=101.157M/s items_per_second=51.7923k/s
hash_4096B             38465 ns        38465 ns        18200 bytes_per_second=101.553M/s items_per_second=25.9975k/s
encrypt_32B_64B          814 ns          814 ns       859990 bytes_per_second=112.486M/s items_per_second=1.22864M/s
encrypt_32B_128B        1300 ns         1299 ns       538874 bytes_per_second=117.423M/s items_per_second=769.543k/s
encrypt_32B_256B        2123 ns         2123 ns       329849 bytes_per_second=129.4M/s items_per_second=471.13k/s
encrypt_32B_512B        3896 ns         3896 ns       179763 bytes_per_second=133.166M/s items_per_second=256.682k/s
encrypt_32B_1024B       7322 ns         7322 ns        95761 bytes_per_second=137.54M/s items_per_second=136.573k/s
encrypt_32B_2048B      14279 ns        14278 ns        49011 bytes_per_second=138.928M/s items_per_second=70.0368k/s
encrypt_32B_4096B      28113 ns        28111 ns        24898 bytes_per_second=140.044M/s items_per_second=35.5732k/s
decrypt_32B_64B          822 ns          821 ns       852537 bytes_per_second=111.446M/s items_per_second=1.21729M/s
decrypt_32B_128B        1303 ns         1303 ns       537255 bytes_per_second=117.102M/s items_per_second=767.441k/s
decrypt_32B_256B        2119 ns         2119 ns       329793 bytes_per_second=129.635M/s items_per_second=471.986k/s
decrypt_32B_512B        3897 ns         3897 ns       179593 bytes_per_second=133.141M/s items_per_second=256.634k/s
decrypt_32B_1024B       7311 ns         7311 ns        95395 bytes_per_second=137.75M/s items_per_second=136.781k/s
decrypt_32B_2048B      14277 ns        14276 ns        49072 bytes_per_second=138.951M/s items_per_second=70.0483k/s
decrypt_32B_4096B      28145 ns        28144 ns        24887 bytes_per_second=139.878M/s items_per_second=35.5313k/s
```

## Usage

Xoodyak being a header-only C++ library, using it is as easy as including [`xoodyak.hpp`](https://github.com/itzmeanjan/xoodyak/blob/f366012/include/xoodyak.hpp) in your C++ program & adding `./include` to your include path. I've written two examples demonstrating usage of Xoodyak C++ API

- Xoodyak Hash; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_hash.cpp) 
- Xoodyak AEAD; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_aead.cpp)
