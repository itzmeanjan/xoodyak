#pragma once
#include "xoodyak.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <cstring>

// Benchmark Xoodyak Authenticated Encryption with Associated Data ( AEAD )
namespace bench_xoodyak {

// Benchmark Xoodyak Cryptographic Hash function on CPU
inline void
hash(benchmark::State& state)
{
  const size_t m_len = state.range(0);

  // allocate memory resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(m_len));
  uint8_t* digest = static_cast<uint8_t*>(malloc(xoodyak::DIGEST_LEN));

  // generate random input bytes for hashing
  xoodyak_utils::random_data(msg, m_len);
  memset(digest, 0, xoodyak::DIGEST_LEN);

  for (auto _ : state) {
    xoodyak::hash(msg, m_len, digest);

    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(digest);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(m_len * state.iterations()));

  // release memory resources
  free(msg);
  free(digest);
}

// Benchmark Xoodyak Authenticated Encryption Algorithm on CPU
inline void
encrypt(benchmark::State& state)
{
  const size_t dt_len = state.range(0);
  const size_t ct_len = state.range(1);
  constexpr size_t knt_len = 16ul;

  // allocate memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  // generate random input bytes for AEAD
  xoodyak_utils::random_data(key, knt_len);
  xoodyak_utils::random_data(nonce, knt_len);
  xoodyak_utils::random_data(data, dt_len);
  xoodyak_utils::random_data(text, ct_len);

  for (auto _ : state) {
    xoodyak::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  bool f = xoodyak::decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

  assert(f);
  for (size_t i = 0; i < ct_len; i++) {
    assert((text[i] ^ dec[i]) == 0u);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // release memory resources
  free(key);
  free(nonce);
  free(tag);
  free(data);
  free(text);
  free(enc);
  free(dec);
}

// Benchmark Xoodyak Verified Decryption Algorithm on CPU
inline void
decrypt(benchmark::State& state)
{
  const size_t dt_len = state.range(0);
  const size_t ct_len = state.range(1);
  constexpr size_t knt_len = 16ul;

  // allocate memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  // generate random input bytes for AEAD
  xoodyak_utils::random_data(key, knt_len);
  xoodyak_utils::random_data(nonce, knt_len);
  xoodyak_utils::random_data(data, dt_len);
  xoodyak_utils::random_data(text, ct_len);

  xoodyak::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  for (auto _ : state) {
    bool f = xoodyak::decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);
    assert(f);

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(tag);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(dec);
    benchmark::DoNotOptimize(f);
    benchmark::ClobberMemory();
  }

  for (size_t i = 0; i < ct_len; i++) {
    assert((text[i] ^ dec[i]) == 0u);
  }

  const size_t per_itr_data = dt_len + ct_len;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  // release memory resources
  free(key);
  free(nonce);
  free(tag);
  free(data);
  free(text);
  free(enc);
  free(dec);
}

}
