#include "bench/bench_xoodyak.hpp"

// Register Xoodyak cryptographic hash function for benchmark with specified
// size of input message bytes
BENCHMARK(bench_xoodyak::hash)->Arg(64);
BENCHMARK(bench_xoodyak::hash)->Arg(128);
BENCHMARK(bench_xoodyak::hash)->Arg(256);
BENCHMARK(bench_xoodyak::hash)->Arg(512);
BENCHMARK(bench_xoodyak::hash)->Arg(1024);
BENCHMARK(bench_xoodyak::hash)->Arg(2048);
BENCHMARK(bench_xoodyak::hash)->Arg(4096);

// Register Xoodyak AEAD encrypt/ decrypt function for benchmark with fixed
// length associated data but variable length plain text
BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 64 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 64 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 128 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 128 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 256 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 256 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 512 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 512 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 1024 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 2048 });

BENCHMARK(bench_xoodyak::encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_xoodyak::decrypt)->Args({ 32, 4096 });

// main function to drive benchmark execution
BENCHMARK_MAIN();
