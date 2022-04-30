#include "xoodyak.hpp"
#include <benchmark/benchmark.h>
#include <string.h>

// Benchmark Xoodyak Cryptographic Hash function on CPU
static void
hash(benchmark::State& state, const size_t m_len)
{
  // allocate memory resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(m_len));
  uint8_t* digest = static_cast<uint8_t*>(malloc(xoodyak::DIGEST_LEN));

  // generate random input bytes for hashing
  random_data(msg, m_len);
  memset(digest, 0, xoodyak::DIGEST_LEN);

  size_t itr = 0;
  for (auto _ : state) {
    xoodyak::hash(msg, m_len, digest);

    benchmark::DoNotOptimize(digest);
    benchmark::DoNotOptimize(itr++);
  }

  state.SetBytesProcessed(static_cast<int64_t>(m_len * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  // release memory resources
  free(msg);
  free(digest);
}

// Xoodyak hash on 32B input
static void
hash_32B(benchmark::State& state)
{
  hash(state, 32ul);
}

// Xoodyak hash on 64B input
static void
hash_64B(benchmark::State& state)
{
  hash(state, 64ul);
}

// Xoodyak hash on 128B input
static void
hash_128B(benchmark::State& state)
{
  hash(state, 128ul);
}

// Xoodyak hash on 0.25KB input
static void
hash_256B(benchmark::State& state)
{
  hash(state, 256ul);
}

// Xoodyak hash on 0.5KB input
static void
hash_512B(benchmark::State& state)
{
  hash(state, 512ul);
}

// Xoodyak hash on 1KB input
static void
hash_1024B(benchmark::State& state)
{
  hash(state, 1024ul);
}

// Xoodyak hash on 2KB input
static void
hash_2048B(benchmark::State& state)
{
  hash(state, 2048ul);
}

// Xoodyak hash on 4KB input
static void
hash_4096B(benchmark::State& state)
{
  hash(state, 4096ul);
}

// register Xoodyak cryptographic hash function for benchmark with specified
// size of input message bytes
BENCHMARK(hash_32B);
BENCHMARK(hash_64B);
BENCHMARK(hash_128B);
BENCHMARK(hash_256B);
BENCHMARK(hash_512B);
BENCHMARK(hash_1024B);
BENCHMARK(hash_2048B);
BENCHMARK(hash_4096B);

// main function to drive benchmark execution
BENCHMARK_MAIN();
