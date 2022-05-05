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
2022-05-05T08:56:57+05:30
Running ./bench/a.out
Run on (4 X 1800 MHz CPU s)
Load Average: 1.45, 0.66, 0.63
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                 803 ns          801 ns       869238 bytes_per_second=38.0901M/s items_per_second=1.24814M/s
hash_64B                1333 ns         1329 ns       526557 bytes_per_second=45.9377M/s items_per_second=752.643k/s
hash_128B               2369 ns         2364 ns       295114 bytes_per_second=51.6394M/s items_per_second=423.03k/s
hash_256B               4734 ns         4534 ns       156153 bytes_per_second=53.8447M/s items_per_second=220.548k/s
hash_512B               8583 ns         8577 ns        79767 bytes_per_second=56.9309M/s items_per_second=116.594k/s
hash_1024B             16898 ns        16888 ns        41411 bytes_per_second=57.8258M/s items_per_second=59.2136k/s
hash_2048B             33518 ns        33496 ns        20877 bytes_per_second=58.3092M/s items_per_second=29.8543k/s
hash_4096B             66741 ns        66683 ns        10472 bytes_per_second=58.5795M/s items_per_second=14.9964k/s
encrypt_32B_64B         1447 ns         1446 ns       483464 bytes_per_second=63.3331M/s items_per_second=691.766k/s
encrypt_32B_128B        2335 ns         2333 ns       299398 bytes_per_second=65.4115M/s items_per_second=428.681k/s
encrypt_32B_256B        4259 ns         3896 ns       183474 bytes_per_second=70.4892M/s items_per_second=256.643k/s
encrypt_32B_512B        7170 ns         7094 ns        97952 bytes_per_second=73.1355M/s items_per_second=140.971k/s
encrypt_32B_1024B      13321 ns        13263 ns        52898 bytes_per_second=75.932M/s items_per_second=75.3982k/s
encrypt_32B_2048B      26026 ns        25925 ns        27039 bytes_per_second=76.5146M/s items_per_second=38.5728k/s
encrypt_32B_4096B      50953 ns        50901 ns        13620 bytes_per_second=77.3411M/s items_per_second=19.6458k/s
decrypt_32B_64B         1497 ns         1480 ns       476973 bytes_per_second=61.8614M/s items_per_second=675.692k/s
decrypt_32B_128B        2385 ns         2369 ns       293295 bytes_per_second=64.4053M/s items_per_second=422.087k/s
decrypt_32B_256B        3835 ns         3833 ns       182543 bytes_per_second=71.655M/s items_per_second=260.888k/s
decrypt_32B_512B        7053 ns         7052 ns        98745 bytes_per_second=73.5724M/s items_per_second=141.813k/s
decrypt_32B_1024B      13242 ns        13235 ns        52683 bytes_per_second=76.0917M/s items_per_second=75.5568k/s
decrypt_32B_2048B      25892 ns        25874 ns        27030 bytes_per_second=76.6648M/s items_per_second=38.6485k/s
decrypt_32B_4096B      50977 ns        50943 ns        13681 bytes_per_second=77.278M/s items_per_second=19.6298k/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-05-05T03:33:03+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.14, 0.06, 0.02
----------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations UserCounters...
----------------------------------------------------------------------------
hash_32B                 525 ns          525 ns      1330691 bytes_per_second=58.1639M/s items_per_second=1.90592M/s
hash_64B                 871 ns          871 ns       803552 bytes_per_second=70.0582M/s items_per_second=1.14783M/s
hash_128B               1566 ns         1566 ns       447110 bytes_per_second=77.9753M/s items_per_second=638.773k/s
hash_256B               2958 ns         2958 ns       236610 bytes_per_second=82.5488M/s items_per_second=338.12k/s
hash_512B               5739 ns         5739 ns       122003 bytes_per_second=85.087M/s items_per_second=174.258k/s
hash_1024B             11284 ns        11284 ns        62052 bytes_per_second=86.5455M/s items_per_second=88.6226k/s
hash_2048B             22400 ns        22400 ns        31255 bytes_per_second=87.193M/s items_per_second=44.6428k/s
hash_4096B             44622 ns        44620 ns        15694 bytes_per_second=87.5446M/s items_per_second=22.4114k/s
encrypt_32B_64B          988 ns          988 ns       709709 bytes_per_second=92.7059M/s items_per_second=1012.6k/s
encrypt_32B_128B        1593 ns         1593 ns       442066 bytes_per_second=95.8083M/s items_per_second=627.889k/s
encrypt_32B_256B        2550 ns         2550 ns       274432 bytes_per_second=107.709M/s items_per_second=392.155k/s
encrypt_32B_512B        4663 ns         4663 ns       150130 bytes_per_second=111.253M/s items_per_second=214.444k/s
encrypt_32B_1024B       8726 ns         8726 ns        80251 bytes_per_second=115.415M/s items_per_second=114.604k/s
encrypt_32B_2048B      17059 ns        17058 ns        41103 bytes_per_second=116.288M/s items_per_second=58.6233k/s
encrypt_32B_4096B      33426 ns        33426 ns        20946 bytes_per_second=117.777M/s items_per_second=29.9172k/s
decrypt_32B_64B         1019 ns         1019 ns       689418 bytes_per_second=89.8509M/s items_per_second=981.412k/s
decrypt_32B_128B        1621 ns         1621 ns       439731 bytes_per_second=94.1436M/s items_per_second=616.98k/s
decrypt_32B_256B        2562 ns         2562 ns       273077 bytes_per_second=107.203M/s items_per_second=390.315k/s
decrypt_32B_512B        4697 ns         4697 ns       148744 bytes_per_second=110.461M/s items_per_second=212.917k/s
decrypt_32B_1024B       8746 ns         8746 ns        79668 bytes_per_second=115.154M/s items_per_second=114.344k/s
decrypt_32B_2048B      17081 ns        17080 ns        40973 bytes_per_second=116.141M/s items_per_second=58.5493k/s
decrypt_32B_4096B      33556 ns        33556 ns        20859 bytes_per_second=117.321M/s items_per_second=29.8013k/s
```

## Usage

Xoodyak being a header-only C++ library, using it is as easy as including [`xoodyak.hpp`](https://github.com/itzmeanjan/xoodyak/blob/f366012/include/xoodyak.hpp) in your C++ program & adding `./include` to your include path. I've written two examples demonstrating usage of Xoodyak C++ API

- Xoodyak Hash; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_hash.cpp) 
- Xoodyak AEAD; see [here](https://github.com/itzmeanjan/xoodyak/blob/f366012/example/xoodyak_aead.cpp)
