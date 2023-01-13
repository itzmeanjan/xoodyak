#pragma once
#include "utils.hpp"
#include "xoodoo.hpp"
#include <benchmark/benchmark.h>

// Benchmark Xoodyak Authenticated Encryption with Associated Data ( AEAD )
namespace bench_xoodyak {

// Benchmarks 12 rounds of Xoodoo permutation
inline void
xoodoo(benchmark::State& state)
{
#if defined __SSE2__ && USE_SSE2 != 0
  alignas(16)
#endif
    uint32_t st[12]{};
  xoodyak_utils::random_data(st, 12);

  for (auto _ : state) {
    xoodoo::permute(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(sizeof(st) * state.iterations());
}

}
