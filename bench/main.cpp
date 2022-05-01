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

// Benchmark Xoodyak Authenticated Encryption on CPU
static void
encrypt(benchmark::State& state, const size_t dt_len, const size_t ct_len)
{
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
  random_data(key, knt_len);
  random_data(nonce, knt_len);
  random_data(data, dt_len);
  random_data(text, ct_len);

  size_t itr = 0;
  for (auto _ : state) {
    xoodyak::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::DoNotOptimize(itr++);
  }

  bool f = xoodyak::decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

  assert(f);
  for (size_t i = 0; i < ct_len; i++) {
    assert((text[i] ^ dec[i]) == 0u);
  }

  state.SetBytesProcessed(static_cast<int64_t>((dt_len + ct_len) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  // release memory resources
  free(key);
  free(nonce);
  free(tag);
  free(data);
  free(text);
  free(enc);
  free(dec);
}

// Benchmark Xoodyak Verified Decryption on CPU
static void
decrypt(benchmark::State& state, const size_t dt_len, const size_t ct_len)
{
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
  random_data(key, knt_len);
  random_data(nonce, knt_len);
  random_data(data, dt_len);
  random_data(text, ct_len);

  xoodyak::encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  size_t itr = 0;
  for (auto _ : state) {
    bool f = xoodyak::decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

    benchmark::DoNotOptimize(f);
    benchmark::DoNotOptimize(dec);
    benchmark::DoNotOptimize(itr++);
  }

  for (size_t i = 0; i < ct_len; i++) {
    assert((text[i] ^ dec[i]) == 0u);
  }

  state.SetBytesProcessed(static_cast<int64_t>((dt_len + ct_len) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  // release memory resources
  free(key);
  free(nonce);
  free(tag);
  free(data);
  free(text);
  free(enc);
  free(dec);
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

static void
encrypt_32B_64B(benchmark::State& state)
{
  encrypt(state, 32ul, 64ul);
}

static void
encrypt_32B_128B(benchmark::State& state)
{
  encrypt(state, 32ul, 128ul);
}

static void
encrypt_32B_256B(benchmark::State& state)
{
  encrypt(state, 32ul, 256ul);
}

static void
encrypt_32B_512B(benchmark::State& state)
{
  encrypt(state, 32ul, 512ul);
}

static void
encrypt_32B_1024B(benchmark::State& state)
{
  encrypt(state, 32ul, 1024ul);
}

static void
encrypt_32B_2048B(benchmark::State& state)
{
  encrypt(state, 32ul, 2048ul);
}

static void
encrypt_32B_4096B(benchmark::State& state)
{
  encrypt(state, 32ul, 4096ul);
}

static void
decrypt_32B_64B(benchmark::State& state)
{
  decrypt(state, 32ul, 64ul);
}

static void
decrypt_32B_128B(benchmark::State& state)
{
  decrypt(state, 32ul, 128ul);
}

static void
decrypt_32B_256B(benchmark::State& state)
{
  decrypt(state, 32ul, 256ul);
}

static void
decrypt_32B_512B(benchmark::State& state)
{
  decrypt(state, 32ul, 512ul);
}

static void
decrypt_32B_1024B(benchmark::State& state)
{
  decrypt(state, 32ul, 1024ul);
}

static void
decrypt_32B_2048B(benchmark::State& state)
{
  decrypt(state, 32ul, 2048ul);
}

static void
decrypt_32B_4096B(benchmark::State& state)
{
  decrypt(state, 32ul, 4096ul);
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

// register Xoodyak AEAD encrypt function for benchmark with fixed length
// associated data but variable length plain text
BENCHMARK(encrypt_32B_64B);
BENCHMARK(encrypt_32B_128B);
BENCHMARK(encrypt_32B_256B);
BENCHMARK(encrypt_32B_512B);
BENCHMARK(encrypt_32B_1024B);
BENCHMARK(encrypt_32B_2048B);
BENCHMARK(encrypt_32B_4096B);

// register Xoodyak AEAD decrypt function for benchmark with fixed length
// associated data but variable length plain text
BENCHMARK(decrypt_32B_64B);
BENCHMARK(decrypt_32B_128B);
BENCHMARK(decrypt_32B_256B);
BENCHMARK(decrypt_32B_512B);
BENCHMARK(decrypt_32B_1024B);
BENCHMARK(decrypt_32B_2048B);
BENCHMARK(decrypt_32B_4096B);

// main function to drive benchmark execution
BENCHMARK_MAIN();
